package retry_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/texas-state-space-lab/pikvm-tailscale-certificate-renewer/internal/retry"
)

const (
	baseWait    = time.Hour
	retryLayout = "2006-01-02 15:04:05 MST"
)

func TestNextStartsAtBase(t *testing.T) {
	t.Parallel()

	if got := retry.Next(nil, baseWait); got != baseWait {
		t.Fatalf("expected %v, got %v", baseWait, got)
	}
}

func TestNextWithoutRetryAfter(t *testing.T) {
	t.Parallel()

	if got := retry.Next(errors.New("context deadline exceeded"), baseWait); got != baseWait {
		t.Fatalf("expected %v, got %v", baseWait, got)
	}
}

func TestNextHonoursRetryAfter(t *testing.T) {
	t.Parallel()

	got := retry.Next(retryAfterError(time.Now().UTC().Add(2*time.Hour)), baseWait)
	if got <= baseWait {
		t.Fatalf("expected more than %v, got %v", baseWait, got)
	}

	if got > 3*time.Hour {
		t.Fatalf("expected at most %v, got %v", 3*time.Hour, got)
	}
}

func TestNextIgnoresPastRetryAfter(t *testing.T) {
	t.Parallel()

	got := retry.Next(retryAfterError(time.Now().UTC().Add(-time.Hour)), baseWait)
	if got != baseWait {
		t.Fatalf("expected %v, got %v", baseWait, got)
	}
}

func TestNextCapsRetryAfter(t *testing.T) {
	t.Parallel()

	got := retry.Next(retryAfterError(time.Now().UTC().Add(30*24*time.Hour)), baseWait)
	if got != retry.MaxAfter {
		t.Fatalf("expected %v, got %v", retry.MaxAfter, got)
	}
}

func TestDouble(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "doubles", in: time.Hour, want: 2 * time.Hour},
		{name: "caps", in: 20 * time.Hour, want: retry.Max},
		{name: "stays at cap", in: retry.Max, want: retry.Max},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := retry.Double(tt.in); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func retryAfterError(after time.Time) error {
	return fmt.Errorf("getCertPEM: 429 rateLimited: retry after %s: see docs",
		after.Format(retryLayout))
}
