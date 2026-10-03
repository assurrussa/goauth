package postgres //nolint:testpackage // Exercise the worker's configured clock through the synthetic SQL driver.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

const notificationClockLease = "lease"

func notificationTestClocks() []struct {
	name string
	now  func() time.Time
} {
	return []struct {
		name string
		now  func() time.Time
	}{
		{"fixed past", func() time.Time { return time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC) }},
		{"fixed future", func() time.Time { return time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC) }},
		{"offset past", func() time.Time { return time.Now().Add(-24 * time.Hour) }},
		{"offset future", func() time.Time { return time.Now().Add(24 * time.Hour) }},
		{"wall clock", time.Now},
	}
}

func TestNotificationConfiguredClockBoundsSendTimeout(t *testing.T) {
	for _, clock := range notificationTestClocks() {
		for _, lifetime := range []time.Duration{time.Minute, time.Hour} {
			t.Run(clock.name+"/"+lifetime.String(), func(t *testing.T) {
				d := &deadlineDriver{}
				var sent bool
				var deadline time.Time
				r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(ctx context.Context, _ goauth.NotificationDelivery) error {
					require.NoError(t, ctx.Err())
					var ok bool
					deadline, ok = ctx.Deadline()
					require.True(t, ok)
					sent = true
					return nil
				}))
				var latestNow time.Time
				r.notificationNow = func() time.Time {
					latestNow = clock.now()
					return latestNow
				}
				r.notificationWorker.SendTimeout = 10 * time.Minute
				r.notificationWorker.LeaseDuration = 20 * time.Minute
				event := deadlineEvent(t, "clock-bound", clock.now().Add(lifetime))
				d.deliveries = []deadlineDelivery{{event: event, token: notificationClockLease, state: notificationLeased}}

				started := time.Now()
				err := r.deliverNotification(context.Background(), notificationClaim{event: event, leaseToken: notificationClockLease})
				finished := time.Now()
				require.NoError(t, err)
				require.True(t, sent, "a notification valid in the configured clock must reach the sender")
				timeout := min(r.notificationWorker.SendTimeout, event.ValidUntil.Sub(latestNow))
				require.WithinRange(t, deadline, started.Add(timeout), finished.Add(timeout))
				require.Equal(t, notificationDelivered, d.deliveries[0].state)
				require.EqualValues(t, 1, d.deliveries[0].attempts)
			})
		}
	}
}

func TestNotificationConfiguredClockRejectsExpired(t *testing.T) {
	for _, clock := range notificationTestClocks() {
		for _, lifetime := range []time.Duration{-time.Second, 0} {
			t.Run(clock.name+"/"+lifetime.String(), func(t *testing.T) {
				d := &deadlineDriver{}
				r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
					t.Error("sender called for an expired notification")
					return nil
				}))
				r.notificationNow = clock.now
				event := deadlineEvent(t, "expired-clock", clock.now().Add(lifetime))
				d.deliveries = []deadlineDelivery{{event: event, token: notificationClockLease, state: notificationLeased}}

				require.NoError(t, r.deliverNotification(context.Background(), notificationClaim{
					event: event, leaseToken: notificationClockLease,
				}))
				require.Equal(t, notificationExpired, d.deliveries[0].state)
				require.Zero(t, d.deliveries[0].attempts)
			})
		}
	}
}

func TestNotificationConfiguredClockRechecksBeforeReservation(t *testing.T) {
	now := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	event := deadlineEvent(t, "expires-before-reservation", now.Add(time.Minute))
	d := &deadlineDriver{deliveries: []deadlineDelivery{{event: event, token: notificationClockLease, state: notificationLeased}}}
	r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
		t.Error("sender called after configured clock reached validity boundary")
		return nil
	}))
	r.notificationNow = func() time.Time {
		current := now
		now = event.ValidUntil
		return current
	}

	require.NoError(t, r.deliverNotification(context.Background(), notificationClaim{
		event: event, leaseToken: notificationClockLease,
	}))
	require.Equal(t, notificationExpired, d.deliveries[0].state)
	require.Zero(t, d.deliveries[0].attempts)
}

func TestNotificationConfiguredClockPreservesParentDeadline(t *testing.T) {
	now := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	event := deadlineEvent(t, "parent-bound", now.Add(time.Hour))
	d := &deadlineDriver{deliveries: []deadlineDelivery{{event: event, token: notificationClockLease, state: notificationLeased}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	parentDeadline, ok := ctx.Deadline()
	require.True(t, ok)
	r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(sendCtx context.Context, _ goauth.NotificationDelivery) error {
		require.NoError(t, sendCtx.Err())
		deadline, ok := sendCtx.Deadline()
		require.True(t, ok)
		require.Equal(t, parentDeadline, deadline)
		cancel()
		require.ErrorIs(t, sendCtx.Err(), context.Canceled)
		return sendCtx.Err()
	}))
	r.notificationNow = func() time.Time { return now }
	r.notificationWorker.SendTimeout = 10 * time.Minute
	r.notificationWorker.LeaseDuration = 20 * time.Minute

	require.ErrorIs(t, r.deliverNotification(ctx, notificationClaim{
		event: event, leaseToken: notificationClockLease,
	}), context.Canceled)
	require.Equal(t, notificationLeased, d.deliveries[0].state)
	require.EqualValues(t, 1, d.deliveries[0].attempts)
}
