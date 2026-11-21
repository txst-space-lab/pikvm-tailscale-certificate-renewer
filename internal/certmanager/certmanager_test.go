package certmanager_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/certmanager"
	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/sslpaths"
)

const (
	testDomain    = "example.ts.net"
	testDay       = 24 * time.Hour
	validPeriod   = 90 * testDay
	renewalPeriod = 10 * testDay
)

func TestCheckCertValid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePair(t, dir, time.Now().Add(validPeriod))

	manager := certmanager.NewCertManager(sslpaths.NewSSLPaths(dir, testDomain))

	if err := manager.CheckCert(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCheckCertNeedsRenewal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePair(t, dir, time.Now().Add(renewalPeriod))

	manager := certmanager.NewCertManager(sslpaths.NewSSLPaths(dir, testDomain))

	if err := manager.CheckCert(); !errors.Is(err, certmanager.ErrCertNeedsRenewal) {
		t.Fatalf("expected ErrCertNeedsRenewal, got %v", err)
	}
}

func TestCheckCertExpired(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePair(t, dir, time.Now().Add(-testDay))

	manager := certmanager.NewCertManager(sslpaths.NewSSLPaths(dir, testDomain))

	if err := manager.CheckCert(); !errors.Is(err, certmanager.ErrCertNeedsRenewal) {
		t.Fatalf("expected ErrCertNeedsRenewal, got %v", err)
	}
}

func TestCheckCertMissingCert(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	manager := certmanager.NewCertManager(sslpaths.NewSSLPaths(dir, testDomain))

	if err := manager.CheckCert(); !errors.Is(err, certmanager.ErrCertDoesNotExist) {
		t.Fatalf("expected ErrCertDoesNotExist, got %v", err)
	}
}

func TestCheckCertMissingKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePair(t, dir, time.Now().Add(validPeriod))

	if err := os.Remove(filepath.Join(dir, testDomain+".key")); err != nil {
		t.Fatalf("failed to remove key: %v", err)
	}

	manager := certmanager.NewCertManager(sslpaths.NewSSLPaths(dir, testDomain))

	if err := manager.CheckCert(); !errors.Is(err, certmanager.ErrKeyDoesNotExist) {
		t.Fatalf("expected ErrKeyDoesNotExist, got %v", err)
	}
}

func TestCheckCertKeyMismatch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePair(t, dir, time.Now().Add(validPeriod))

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	writeKey(t, dir, testDomain, otherKey)

	manager := certmanager.NewCertManager(sslpaths.NewSSLPaths(dir, testDomain))

	if err := manager.CheckCert(); !errors.Is(err, certmanager.ErrKeyDoesNotMatch) {
		t.Fatalf("expected ErrKeyDoesNotMatch, got %v", err)
	}
}

func TestCheckCertWrongDomain(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePairForDomain(t, dir, testDomain, "other.ts.net", time.Now().Add(validPeriod))

	manager := certmanager.NewCertManager(sslpaths.NewSSLPaths(dir, testDomain))

	if err := manager.CheckCert(); !errors.Is(err, certmanager.ErrCertDoesNotMatch) {
		t.Fatalf("expected ErrCertDoesNotMatch, got %v", err)
	}
}

func writePair(t *testing.T, dir string, notAfter time.Time) {
	t.Helper()

	writePairForDomain(t, dir, testDomain, testDomain, notAfter)
}

func writePairForDomain(t *testing.T, dir, fileDomain, certDomain string, notAfter time.Time) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: certDomain},
		DNSNames:              []string{certDomain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if err := os.WriteFile(filepath.Join(dir, fileDomain+".crt"), certPEM, 0o600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}

	writeKey(t, dir, fileDomain, key)
}

func writeKey(t *testing.T, dir, domain string, key *ecdsa.PrivateKey) {
	t.Helper()

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(dir, domain+".key"), keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
}
