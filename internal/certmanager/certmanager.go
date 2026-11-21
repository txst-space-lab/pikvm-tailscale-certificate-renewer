package certmanager

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/pikvm"
	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/sslpaths"
	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/tailscale"
)

type CertManager struct {
	ssl *sslpaths.SSLPaths
}

func NewCertManager(ssl *sslpaths.SSLPaths) *CertManager {
	return &CertManager{
		ssl: ssl,
	}
}

const (
	certDirPerms  = 0o755
	certFilePerms = 0o644
	renewalWindow = 30 * 24 * time.Hour
)

var (
	ErrCertDoesNotExist = errors.New("cert does not exist")
	ErrKeyDoesNotExist  = errors.New("key does not exist")
	ErrCertDoesNotMatch = errors.New("cert does not match")
	ErrKeyDoesNotMatch  = errors.New("key does not match")
	ErrCertNeedsRenewal = errors.New("cert needs renewal")
)

// CheckCert checks that the local cert and key exist, match each other and the
// configured domain, and are valid beyond the renewal window. It never contacts
// tailscaled, so a stalled cert request cannot block this check.
func (c *CertManager) CheckCert() error {
	certPEM, err := os.ReadFile(c.ssl.GetCertPath())
	if errors.Is(err, fs.ErrNotExist) {
		slog.Warn("cert file does not exist", "path", c.ssl.GetCertPath())

		return ErrCertDoesNotExist
	}

	if err != nil {
		return fmt.Errorf("failed to read cert file: %w", err)
	}

	keyPEM, err := os.ReadFile(c.ssl.GetKeyPath())
	if errors.Is(err, fs.ErrNotExist) {
		slog.Warn("key file does not exist", "path", c.ssl.GetKeyPath())

		return ErrKeyDoesNotExist
	}

	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	cert, err := parseCert(certPEM)
	if err != nil {
		slog.Warn("cert is not valid", "path", c.ssl.GetCertPath(), "error", err)

		return ErrCertDoesNotMatch
	}

	if err := cert.VerifyHostname(c.ssl.GetDomain()); err != nil {
		slog.Warn("cert does not match domain", "domain", c.ssl.GetDomain(), "error", err)

		return ErrCertDoesNotMatch
	}

	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		slog.Warn("key does not match cert", "path", c.ssl.GetKeyPath(), "error", err)

		return ErrKeyDoesNotMatch
	}

	if time.Until(cert.NotAfter) <= renewalWindow {
		slog.Info("cert needs renewal", "not_after", cert.NotAfter, "renewal_window", renewalWindow)

		return ErrCertNeedsRenewal
	}

	return nil
}

func parseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode cert PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %w", err)
	}

	return cert, nil
}

// GenerateCert asks tailscaled for a new cert pair and writes it to disk.
func (c *CertManager) GenerateCert(ctx context.Context) error {
	cert, key, err := tailscale.CertPair(ctx, c.ssl.GetDomain())
	if err != nil {
		return fmt.Errorf("failed to get tailscale cert pair: %w", err)
	}

	if err := validateCertPair(cert, key, c.ssl.GetDomain()); err != nil {
		return err
	}

	if err := pikvm.SetFSReadWrite(); err != nil {
		return fmt.Errorf("failed filesystem mode change: %w", err)
	}

	defer func() {
		if err := pikvm.SetFSReadOnly(); err != nil {
			slog.Error("failed filesystem mode change", "error", err)
		}
	}()

	if err := os.MkdirAll(c.ssl.GetDir(), certDirPerms); err != nil {
		return fmt.Errorf("failed to create cert path: %w", err)
	}

	if err := writeFileAtomic(c.ssl.GetCertPath(), cert, certFilePerms); err != nil {
		return fmt.Errorf("failed to write cert file: %w", err)
	}

	slog.Info("wrote cert file", "path", c.ssl.GetCertPath())

	if err := writeFileAtomic(c.ssl.GetKeyPath(), key, certFilePerms); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	slog.Info("wrote key file", "path", c.ssl.GetKeyPath())

	return nil
}

func validateCertPair(cert, key []byte, domain string) error {
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return fmt.Errorf("tailscale returned an invalid cert pair: %w", err)
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse tailscale cert: %w", err)
	}

	if err := leaf.VerifyHostname(domain); err != nil {
		return fmt.Errorf("tailscale cert does not match domain: %w", err)
	}

	return nil
}

func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	tmpPath := path + ".tmp"

	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)

		return fmt.Errorf("failed to replace file: %w", err)
	}

	return nil
}
