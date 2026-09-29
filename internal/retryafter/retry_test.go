package retryafter

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

type delayedError time.Duration

func (e delayedError) Error() string             { return "rate limited" }
func (e delayedError) RetryAfter() time.Duration { return time.Duration(e) }

func TestSeconds(t *testing.T) {
	for _, tc := range []struct {
		delay time.Duration
		want  int
	}{
		{-time.Second, 1},
		{0, 1},
		{time.Second, 1},
		{time.Second + time.Nanosecond, 2},
		{17 * time.Second, 17},
		{24 * time.Hour, 86400},
	} {
		for _, err := range []error{
			delayedError(tc.delay),
			fmt.Errorf("wrapped: %w", delayedError(tc.delay)),
			errors.Join(errors.New("context"), delayedError(tc.delay)),
		} {
			if got, ok := Seconds(err); !ok || got != tc.want {
				t.Fatalf("delay %v: got (%d,%v), want %d", tc.delay, got, ok, tc.want)
			}
		}
	}
	if _, ok := Seconds(errors.New("plain")); ok {
		t.Fatal("plain errors must not acquire a retry hint")
	}
	if _, ok := Seconds(nil); ok {
		t.Fatal("nil errors must not acquire a retry hint")
	}
}
