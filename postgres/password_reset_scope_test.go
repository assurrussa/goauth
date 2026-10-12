package postgres //nolint:testpackage // Tests the worker's authenticated-context boundary.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestPasswordResetWorkerRestoresAuthenticatedScope(t *testing.T) {
	ambient, err := goauth.WithPasswordResetScope(t.Context(), "ambient-v1")
	require.NoError(t, err)
	for _, kind := range []string{"password_reset", "password_reset_success"} {
		for _, scope := range []string{"", "operator-v1", "sso-v1"} {
			t.Run(kind+"/"+scope, func(t *testing.T) {
				calls := 0
				runtime := &Runtime{notificationSender: goauth.NotificationSenderFunc(
					func(ctx context.Context, _ goauth.NotificationDelivery) error {
						calls++
						require.Equal(t, scope, goauth.PasswordResetScope(ctx))
						return nil
					},
				)}
				notification := goauth.Notification{Template: kind}
				if scope != "" {
					notification.Data = map[string]string{"password_reset_scope": scope}
				}
				// deliverNotification decrypts the sealed event before this helper.
				require.NoError(t, runtime.sendCurrentPasswordResetNotification(ambient,
					goauth.EncryptedEvent{Type: kind, ValidUntil: time.Now().Add(time.Minute)}, notification))
				require.Equal(t, 1, calls)
			})
		}
	}
}

func TestPasswordResetWorkerRejectsMalformedAuthenticatedScope(t *testing.T) {
	calls := 0
	runtime := &Runtime{notificationSender: goauth.NotificationSenderFunc(
		func(context.Context, goauth.NotificationDelivery) error {
			calls++
			return nil
		},
	)}
	for _, kind := range []string{"password_reset", "password_reset_success"} {
		err := runtime.sendCurrentPasswordResetNotification(t.Context(), goauth.EncryptedEvent{Type: kind},
			goauth.Notification{Template: kind, Data: map[string]string{"password_reset_scope": "../operator"}})
		require.ErrorIs(t, err, errPasswordResetNotificationStale)
	}
	require.Zero(t, calls)
}
