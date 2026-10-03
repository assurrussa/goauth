package postgres //nolint:testpackage // Reuses the lease-owning worker driver.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestManagedSenderRejectionIsTerminalWithoutDelivery(t *testing.T) {
	d := &deadlineDriver{deliveries: []deadlineDelivery{{event: deadlineEvent(t, "rejected", time.Now().Add(time.Hour))}}}
	calls := 0
	r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
		calls++
		return errors.Join(goauth.ErrNotificationRejected, errors.New("private-provider-secret"))
	}))
	claim, err := r.store.claimNotification(t.Context(), time.Now(), time.Minute)
	require.NoError(t, err)
	require.NoError(t, r.deliverNotification(t.Context(), claim))
	require.Equal(t, 1, calls)
	require.Equal(t, notificationExhausted, d.deliveries[0].state)
	require.EqualValues(t, 1, d.deliveries[0].attempts)
	require.Empty(t, d.deliveries[0].token)
	_, err = r.store.claimNotification(t.Context(), time.Now().Add(time.Minute), time.Minute)
	require.Error(t, err)
	require.Equal(t, 1, calls)
}

func TestNotificationExpiryRejectsInvalidRuntime(t *testing.T) {
	for _, runtime := range []*Runtime{nil, {}} {
		_, err := runtime.ExpireNotifications(t.Context(), 100)
		require.ErrorContains(t, err, "not initialized")
	}
}

func TestNotificationExpiryRejectsForeignTransaction(t *testing.T) {
	owner := &Store{db: openNotificationRecordingDB(t, "expiry-owner")}
	foreign := &Runtime{store: &Store{db: openNotificationRecordingDB(t, "expiry-foreign")}, notificationNow: time.Now}
	resetNotificationTrace()
	err := owner.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		_, expireErr := foreign.ExpireNotifications(ctx, 1)
		require.ErrorIs(t, expireErr, errForeignNotificationTransaction)
		return nil
	})
	require.NoError(t, err)
	require.Empty(t, notificationWrites())
}

func TestManagedSenderRejectionCannotOverwriteReclaimedLease(t *testing.T) {
	d := &deadlineDriver{deliveries: []deadlineDelivery{{event: deadlineEvent(t, "reclaimed", time.Now().Add(time.Hour))}}}
	r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
		d.deliveries[0].token = "new-owner"
		return goauth.ErrNotificationRejected
	}))
	claim, err := r.store.claimNotification(t.Context(), time.Now(), time.Minute)
	require.NoError(t, err)
	require.NoError(t, r.deliverNotification(t.Context(), claim))
	require.Equal(t, notificationLeased, d.deliveries[0].state)
	require.Equal(t, "new-owner", d.deliveries[0].token)
}
