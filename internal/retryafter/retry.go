// Package retryafter extracts a transport-independent retry deadline.
package retryafter

import (
	"errors"
	"time"
)

// Seconds supports wrapped and joined errors without importing the root Runtime.
// The caller must give uncertain operation outcomes precedence over this hint.
func Seconds(err error) (int, bool) {
	var retry interface{ RetryAfter() time.Duration }
	if !errors.As(err, &retry) {
		return 0, false
	}
	delay := retry.RetryAfter()
	if delay <= time.Second {
		return 1, true
	}
	seconds := int64(delay / time.Second)
	if delay%time.Second != 0 {
		seconds++
	}
	maxInt := int64(^uint(0) >> 1)
	if seconds > maxInt {
		seconds = maxInt
	}
	return int(seconds), true
}
