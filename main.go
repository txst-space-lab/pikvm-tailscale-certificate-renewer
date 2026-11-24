package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	systemd "github.com/coreos/go-systemd/v22/daemon"
	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/certmanager"
	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/pikvm"
	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/retry"
	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/sslpaths"
	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/tailscale"
)

const (
	checkInterval   = 1 * time.Hour
	retryInterval   = 1 * time.Hour
	workTimeout     = 15 * time.Minute
	watchdogDivisor = 3
)

func main() {
	ctx := context.Background()

	slog.Info("starting tailscale cert renewer")

	if err := notifyReady(); err != nil {
		slog.Error("failed to notify systemd", "error", err)
		os.Exit(1)
	}

	startWatchdog(ctx)

	retryDelay := retryInterval

	for {
		if err := renewOnce(ctx); err != nil {
			wait := retry.Next(err, retryDelay)
			slog.Error("failed to check or renew cert", "time_until_retry", wait, "error", err)
			time.Sleep(wait)

			retryDelay = retry.Double(retryDelay)

			continue
		}

		retryDelay = retryInterval

		time.Sleep(checkInterval)
	}
}

func notifyReady() error {
	ok, err := systemd.SdNotify(false, systemd.SdNotifyReady)
	if err != nil {
		return fmt.Errorf("failed to notify systemd: %w", err)
	}

	if !ok {
		return errors.New("systemd notify socket is unset")
	}

	return nil
}

// startWatchdog feeds the systemd watchdog from its own goroutine. The renewal
// work can block for minutes in tailscaled, so pinging from the work loop lets
// the watchdog kill the service in the middle of a cert fetch.
func startWatchdog(ctx context.Context) {
	timeout, err := systemd.SdWatchdogEnabled(false)
	if err != nil {
		slog.Warn("failed to read systemd watchdog timeout", "error", err)

		return
	}

	if timeout <= 0 {
		slog.Info("systemd watchdog is disabled")

		return
	}

	interval := timeout / watchdogDivisor
	if interval <= 0 {
		interval = timeout
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := systemd.SdNotify(false, systemd.SdNotifyWatchdog); err != nil {
					slog.Error("failed to notify systemd watchdog", "error", err)
				}
			}
		}
	}()
}

func renewOnce(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, workTimeout)
	defer cancel()

	return doCertCheckAndRenewal(ctx)
}

func doCertCheckAndRenewal(ctx context.Context) error {
	domain, err := tailscale.GetDomain(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tailscale domain: %w", err)
	}

	if domain == "" {
		return errors.New("tailscale domain is empty")
	}

	ssl := sslpaths.NewSSLPaths("/etc/kvmd/nginx/ssl/", domain)
	certManager := certmanager.NewCertManager(ssl)

	sslCertsChanged, err := changedSSLCerts(ctx, certManager)
	if err != nil {
		return fmt.Errorf("failed to check ssl certs: %w", err)
	}

	nginxConfigChanged, err := changedNginxConfig(ssl)
	if err != nil {
		return fmt.Errorf("failed to check nginx config: %w", err)
	}

	if sslCertsChanged || nginxConfigChanged {
		if err := pikvm.RestartNginx(); err != nil {
			return fmt.Errorf("failed to restart nginx: %w", err)
		}
	}

	return nil
}

func changedSSLCerts(ctx context.Context, certManager *certmanager.CertManager) (bool, error) {
	err := certManager.CheckCert()
	if errors.Is(err, certmanager.ErrCertDoesNotExist) ||
		errors.Is(err, certmanager.ErrKeyDoesNotExist) ||
		errors.Is(err, certmanager.ErrCertDoesNotMatch) ||
		errors.Is(err, certmanager.ErrKeyDoesNotMatch) ||
		errors.Is(err, certmanager.ErrCertNeedsRenewal) {
		if err := certManager.GenerateCert(ctx); err != nil {
			return false, fmt.Errorf("failed to generate cert: %w", err)
		}

		return true, nil
	}

	if err != nil {
		return false, fmt.Errorf("failed to check cert: %w", err)
	}

	return false, nil
}

func changedNginxConfig(ssl *sslpaths.SSLPaths) (bool, error) {
	if err := pikvm.CheckNginxConfig(ssl); errors.Is(err, pikvm.ErrNginxConfigMissingSSLDetails) {
		if err := pikvm.WriteNginxConfig(ssl); err != nil {
			return false, fmt.Errorf("failed to write nginx config: %w", err)
		}

		return true, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to set certs in nginx config: %w", err)
	}

	return false, nil
}
