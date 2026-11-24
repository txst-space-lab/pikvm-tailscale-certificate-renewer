// Package retry chooses how long the renewer waits before its next attempt.
package retry

import (
	"regexp"
	"time"
)

const (
	// Max is the longest wait the exponential backoff chooses by itself.
	Max = 24 * time.Hour
	// MaxAfter bounds a retry-after read from an error, so a bad clock cannot
	// stall the renewer for longer than a week.
	MaxAfter = 168 * time.Hour
	// Margin keeps the next attempt clear of a retry-after boundary.
	Margin = 5 * time.Minute

	timeLayout = "2006-01-02 15:04:05 MST"
)

// Next returns how long to wait after err, starting from base. A retry-after
// time embedded in the error wins when it is later than base, which is what
// Let's Encrypt returns with an ACME rate-limit rejection.
func Next(err error, base time.Duration) time.Duration {
	wait := base
	if wait > Max {
		wait = Max
	}

	if err == nil {
		return wait
	}

	if after, ok := retryAfter(err); ok {
		until := time.Until(after) + Margin
		if until > wait {
			wait = until
		}
	}

	if wait > MaxAfter {
		wait = MaxAfter
	}

	return wait
}

// Double returns the next exponential base, capped at Max.
func Double(base time.Duration) time.Duration {
	next := base + base
	if next > Max {
		return Max
	}

	return next
}

func retryAfter(err error) (time.Time, bool) {
	re := regexp.MustCompile(`retry after (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)`)

	match := re.FindStringSubmatch(err.Error())
	if match == nil {
		return time.Time{}, false
	}

	after, parseErr := time.Parse(timeLayout, match[1])
	if parseErr != nil {
		return time.Time{}, false
	}

	return after, true
}
