package postgres //nolint:testpackage // Verify the private persistence boundary.

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type diagnosticFailure struct{ diagnostic goauth.NotificationDiagnostic }

func (e diagnosticFailure) Error() string { panic("raw sender error must never be inspected") }
func (e diagnosticFailure) NotificationDiagnostic() goauth.NotificationDiagnostic {
	return e.diagnostic
}

func TestSenderDiagnosticStrictAllowlist(t *testing.T) {
	valid := []goauth.NotificationDiagnostic{
		{Outcome: "not_sent", Code: "invalid_request", HTTPStatus: 0},
		{Outcome: "not_sent", Code: "unauthorized", HTTPStatus: 401},
		{Outcome: "not_sent", Code: "quota_exceeded", HTTPStatus: 429},
		{Outcome: "unknown", Code: "request_failed", HTTPStatus: 0},
		{Outcome: "unknown", Code: "invalid_response", HTTPStatus: 502},
		{Outcome: "unknown", Code: "dispatch_in_progress", HTTPStatus: 202},
		{Outcome: "unknown", Code: "dispatch_outcome_unknown", HTTPStatus: 409},
		{Outcome: "retryable", Code: "provider_rejected_temporary", HTTPStatus: 503},
		{Outcome: "rejected", Code: "recipient_suppressed", HTTPStatus: 422},
		{Outcome: "simulated", Code: "dry_run_no_external_delivery", HTTPStatus: 200},
	}
	for _, d := range valid {
		t.Run(d.Code, func(t *testing.T) {
			var err error = diagnosticFailure{d}
			if d.Outcome == "rejected" || d.Outcome == "simulated" {
				err = errors.Join(err, goauth.ErrNotificationRejected)
			}
			require.Equal(t, &d, notificationSenderDiagnostic(err))
		})
	}
	for _, d := range []goauth.NotificationDiagnostic{
		{Outcome: "accepted", Code: "unauthorized", HTTPStatus: 401},
		{Outcome: "not_sent", Code: "unauthorized", HTTPStatus: 503},
		{Outcome: "not_sent", Code: "private@example.test", HTTPStatus: 401},
		{Outcome: "unknown", Code: "invalid_response", HTTPStatus: 401},
		{Outcome: "unknown", Code: "invalid_response", HTTPStatus: 999},
		{Outcome: "unknown", Code: "request_failed", HTTPStatus: 200},
		{Outcome: "retryable", Code: "provider_rejected", HTTPStatus: 503},
		{Outcome: "not_sent", Code: "unauthorized\nBearer secret", HTTPStatus: 401},
	} {
		require.Nil(t, notificationSenderDiagnostic(diagnosticFailure{d}))
	}
	require.Nil(t, notificationSenderDiagnostic(nil))
	require.Nil(t, notificationSenderDiagnostic(errors.New("raw private response")))
	require.Nil(t, notificationSenderDiagnostic(diagnosticFailure{goauth.NotificationDiagnostic{Outcome: "rejected", Code: "failed", HTTPStatus: 422}}))
	require.Nil(t, notificationSenderDiagnostic(errors.Join(goauth.ErrNotificationRejected, diagnosticFailure{valid[1]})))
	wrapped := fmt.Errorf("safe wrapper: %w", errors.New("legacy"))
	require.Nil(t, notificationSenderDiagnostic(wrapped))
}

func TestSenderDiagnosticAtomicSettlement(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprint(terminal), func(t *testing.T) {
			d := &deadlineDriver{deliveries: []deadlineDelivery{{event: deadlineEvent(t, "diagnostic", time.Now().Add(time.Hour))}}}
			diagnostic := goauth.NotificationDiagnostic{Outcome: "not_sent", Code: "unauthorized", HTTPStatus: 401}
			if terminal {
				diagnostic = goauth.NotificationDiagnostic{Outcome: "rejected", Code: "failed", HTTPStatus: 422}
			}
			r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
				if terminal {
					return errors.Join(goauth.ErrNotificationRejected, diagnosticFailure{diagnostic})
				}
				return diagnosticFailure{diagnostic}
			}))
			claim, err := r.store.claimNotification(t.Context(), time.Now(), time.Minute)
			require.NoError(t, err)
			require.NoError(t, r.deliverNotification(t.Context(), claim))
			require.Equal(t, []driver.Value{diagnostic.Outcome, diagnostic.Code, int64(diagnostic.HTTPStatus), d.deliveries[0].diagnostic[3]}, d.deliveries[0].diagnostic)
			require.IsType(t, time.Time{}, d.deliveries[0].diagnostic[3])
			require.EqualValues(t, 1, d.deliveries[0].attempts)
			if terminal {
				require.Equal(t, notificationExhausted, d.deliveries[0].state)
			} else {
				require.Equal(t, notificationPending, d.deliveries[0].state)
			}
		})
	}
}

func TestSenderDiagnosticCannotOverwriteLostLease(t *testing.T) {
	d := &deadlineDriver{deliveries: []deadlineDelivery{{event: deadlineEvent(t, "lost", time.Now().Add(time.Hour))}}}
	r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
		d.deliveries[0].token = "new-owner"
		d.deliveries[0].diagnostic = []driver.Value{"newer"}
		return diagnosticFailure{goauth.NotificationDiagnostic{Outcome: "not_sent", Code: "unauthorized", HTTPStatus: 401}}
	}))
	claim, err := r.store.claimNotification(t.Context(), time.Now(), time.Minute)
	require.NoError(t, err)
	require.NoError(t, r.deliverNotification(t.Context(), claim))
	require.Equal(t, []driver.Value{"newer"}, d.deliveries[0].diagnostic)
}

func TestSenderDiagnosticClearedForLegacyAndAccepted(t *testing.T) {
	for _, senderErr := range []error{nil, errors.New("private legacy failure"), goauth.ErrNotificationRejected} {
		d := &deadlineDriver{deliveries: []deadlineDelivery{{event: deadlineEvent(t, "legacy", time.Now().Add(time.Hour)), diagnostic: []driver.Value{"old"}}}}
		r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
			require.Empty(t, d.deliveries[0].diagnostic)
			return senderErr
		}))
		claim, err := r.store.claimNotification(t.Context(), time.Now(), time.Minute)
		require.NoError(t, err)
		require.NoError(t, r.deliverNotification(t.Context(), claim))
		require.Equal(t, []driver.Value{nil, nil, nil, nil}, d.deliveries[0].diagnostic)
	}
}
