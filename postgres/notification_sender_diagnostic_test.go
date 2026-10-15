package postgres //nolint:testpackage // Verify the private persistence boundary.

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type diagnosticError struct{ diagnostic goauth.NotificationDiagnostic }

func (e diagnosticError) Error() string { panic("raw sender error must never be inspected") }
func (e diagnosticError) NotificationDiagnostic() goauth.NotificationDiagnostic {
	return e.diagnostic
}

func TestSenderDiagnosticStrictAllowlist(t *testing.T) {
	valid := []goauth.NotificationDiagnostic{
		{Outcome: senderOutcomeNotSent, Code: "invalid_request", HTTPStatus: 0},
		{Outcome: senderOutcomeNotSent, Code: senderCodeUnauthorized, HTTPStatus: 401},
		{Outcome: senderOutcomeNotSent, Code: "quota_exceeded", HTTPStatus: 429},
		{Outcome: senderOutcomeUnknown, Code: "request_failed", HTTPStatus: 0},
		{Outcome: senderOutcomeUnknown, Code: senderCodeInvalidResponse, HTTPStatus: 502},
		{Outcome: senderOutcomeUnknown, Code: "dispatch_in_progress", HTTPStatus: 202},
		{Outcome: senderOutcomeUnknown, Code: "dispatch_outcome_unknown", HTTPStatus: 409},
		{Outcome: "retryable", Code: "provider_rejected_temporary", HTTPStatus: 503},
		{Outcome: senderOutcomeRejected, Code: "recipient_suppressed", HTTPStatus: 422},
		{Outcome: senderOutcomeSimulated, Code: "dry_run_no_external_delivery", HTTPStatus: 200},
	}
	for _, d := range valid {
		t.Run(d.Code, func(t *testing.T) {
			var err error = diagnosticError{d}
			if d.Outcome == senderOutcomeRejected || d.Outcome == senderOutcomeSimulated {
				err = errors.Join(err, goauth.ErrNotificationRejected)
			}
			require.Equal(t, &d, notificationSenderDiagnostic(err))
		})
	}
	for _, d := range []goauth.NotificationDiagnostic{
		{Outcome: "accepted", Code: senderCodeUnauthorized, HTTPStatus: 401},
		{Outcome: senderOutcomeNotSent, Code: senderCodeUnauthorized, HTTPStatus: 503},
		{Outcome: senderOutcomeNotSent, Code: "private@example.test", HTTPStatus: 401},
		{Outcome: senderOutcomeUnknown, Code: senderCodeInvalidResponse, HTTPStatus: 401},
		{Outcome: senderOutcomeUnknown, Code: senderCodeInvalidResponse, HTTPStatus: 999},
		{Outcome: senderOutcomeUnknown, Code: "request_failed", HTTPStatus: 200},
		{Outcome: "retryable", Code: "provider_rejected", HTTPStatus: 503},
		{Outcome: senderOutcomeNotSent, Code: "unauthorized\nBearer secret", HTTPStatus: 401},
	} {
		require.Nil(t, notificationSenderDiagnostic(diagnosticError{d}))
	}
	require.Nil(t, notificationSenderDiagnostic(nil))
	require.Nil(t, notificationSenderDiagnostic(errors.New("raw private response")))
	require.Nil(t, notificationSenderDiagnostic(diagnosticError{goauth.NotificationDiagnostic{
		Outcome: senderOutcomeRejected, Code: "failed", HTTPStatus: 422,
	}}))
	require.Nil(t, notificationSenderDiagnostic(errors.Join(goauth.ErrNotificationRejected, diagnosticError{valid[1]})))
	wrapped := fmt.Errorf("safe wrapper: %w", errors.New("legacy"))
	require.Nil(t, notificationSenderDiagnostic(wrapped))
}

func TestSenderDiagnosticAtomicSettlement(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(strconv.FormatBool(terminal), func(t *testing.T) {
			d := &deadlineDriver{deliveries: []deadlineDelivery{{event: deadlineEvent(t, "diagnostic", time.Now().Add(time.Hour))}}}
			diagnostic := goauth.NotificationDiagnostic{Outcome: senderOutcomeNotSent, Code: senderCodeUnauthorized, HTTPStatus: 401}
			if terminal {
				diagnostic = goauth.NotificationDiagnostic{Outcome: senderOutcomeRejected, Code: "failed", HTTPStatus: 422}
			}
			r := deadlineRuntime(t, d, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
				if terminal {
					return errors.Join(goauth.ErrNotificationRejected, diagnosticError{diagnostic})
				}
				return diagnosticError{diagnostic}
			}))
			claim, err := r.store.claimNotification(t.Context(), time.Now(), time.Minute)
			require.NoError(t, err)
			require.NoError(t, r.deliverNotification(t.Context(), claim))
			require.Equal(t, []driver.Value{
				diagnostic.Outcome, diagnostic.Code, int64(diagnostic.HTTPStatus), d.deliveries[0].diagnostic[3],
			}, d.deliveries[0].diagnostic)
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
		d.deliveries[0].token = deadlineReclaimedOwner
		d.deliveries[0].diagnostic = []driver.Value{"newer"}
		return diagnosticError{goauth.NotificationDiagnostic{
			Outcome: senderOutcomeNotSent, Code: senderCodeUnauthorized, HTTPStatus: 401,
		}}
	}))
	claim, err := r.store.claimNotification(t.Context(), time.Now(), time.Minute)
	require.NoError(t, err)
	require.NoError(t, r.deliverNotification(t.Context(), claim))
	require.Equal(t, []driver.Value{"newer"}, d.deliveries[0].diagnostic)
}

func TestSenderDiagnosticClearedForLegacyAndAccepted(t *testing.T) {
	for _, senderErr := range []error{nil, errors.New("private legacy failure"), goauth.ErrNotificationRejected} {
		d := &deadlineDriver{deliveries: []deadlineDelivery{{
			event: deadlineEvent(t, "legacy", time.Now().Add(time.Hour)), diagnostic: []driver.Value{"old"},
		}}}
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
