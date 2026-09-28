package postgres //nolint:testpackage // Exercise the private bounded retry policy directly.

import (
	"testing"
	"time"
)

func TestNotificationWorkerDefaultsAndBoundedRetry(t *testing.T) {
	config, err := (NotificationWorkerConfig{}).withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if config.Workers != 1 || config.PollInterval != time.Second || config.MaxAttempts != 10 {
		t.Fatalf("unexpected notification worker defaults: %+v", config)
	}
	for _, test := range []struct {
		attempts int
		want     time.Duration
	}{
		{0, time.Second},
		{1, 2 * time.Second},
		{5, 32 * time.Second},
		{6, time.Minute},
		{20, time.Minute},
	} {
		if got := notificationBackoff(config, test.attempts); got != test.want {
			t.Errorf("attempts=%d: backoff=%s, want %s", test.attempts, got, test.want)
		}
	}
	for _, invalid := range []NotificationWorkerConfig{
		{Workers: -1},
		{Workers: 33},
		{PollInterval: time.Nanosecond},
		{SendTimeout: time.Minute, LeaseDuration: time.Second},
		{RetryMin: time.Minute, RetryMax: time.Second},
		{MaxAttempts: 101},
	} {
		if _, err := invalid.withDefaults(); err == nil {
			t.Errorf("accepted invalid notification worker settings: %+v", invalid)
		}
	}
}
