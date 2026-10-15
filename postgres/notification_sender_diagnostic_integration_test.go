//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type safeSenderFailure struct{ value goauth.NotificationDiagnostic }

func (e safeSenderFailure) Error() string                                         { return "private-address@example.test Bearer private-token" }
func (e safeSenderFailure) NotificationDiagnostic() goauth.NotificationDiagnostic { return e.value }

func TestManagedSenderDiagnosticPersistsWithTerminalReceipt(t *testing.T) {
	db := integrationDB(t)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
		return errors.Join(goauth.ErrNotificationRejected, safeSenderFailure{goauth.NotificationDiagnostic{Outcome: "rejected", Code: "recipient_suppressed", HTTPStatus: 422}})
	}))
	account := register(t, runtime, "sender-diagnostic@example.test")
	require.NoError(t, runtime.SendEmailChallenge(t.Context(), account.Account.Subject.ID, goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, account.Account.Subject.ID)
	startManagedNotificationWorker(t, runtime)
	waitManagedNotificationState(t, db, id, "exhausted")
	var outcome, code, failure string
	var status, attempt, attempts int
	var observed time.Time
	var accepted bool
	require.NoError(t, db.QueryRow(`SELECT last_sender_outcome,last_sender_code,last_sender_http_status,
 last_sender_attempt,last_sender_observed_at,attempts,last_failure,delivered_at IS NOT NULL
 FROM auth_notification_deliveries WHERE id=$1`, id).Scan(&outcome, &code, &status, &attempt, &observed, &attempts, &failure, &accepted))
	require.Equal(t, "rejected", outcome)
	require.Equal(t, "recipient_suppressed", code)
	require.Equal(t, 422, status)
	require.Equal(t, 1, attempt)
	require.Equal(t, attempts, attempt)
	require.False(t, observed.IsZero())
	require.Equal(t, "sender_rejected", failure)
	require.False(t, accepted)
	var receipt string
	require.NoError(t, db.QueryRow(`SELECT to_jsonb(n)::text FROM auth_notification_deliveries n WHERE id=$1`, id).Scan(&receipt))
	require.NotContains(t, receipt, "private-token")
	require.NotContains(t, receipt, "private-address")
}

func TestManagedSenderDiagnosticRejectsMalformedTuple(t *testing.T) {
	db := integrationDB(t)
	runtime := managedNotificationRuntime(t, db, goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
		return errors.Join(goauth.ErrNotificationRejected, safeSenderFailure{goauth.NotificationDiagnostic{Outcome: "rejected", Code: "private-token", HTTPStatus: 422}})
	}))
	account := register(t, runtime, "malformed-diagnostic@example.test")
	require.NoError(t, runtime.SendEmailChallenge(t.Context(), account.Account.Subject.ID, goauth.EmailChallengePurposeVerification))
	id := managedNotificationID(t, db, account.Account.Subject.ID)
	startManagedNotificationWorker(t, runtime)
	waitManagedNotificationState(t, db, id, "exhausted")
	var outcome, code sql.NullString
	var status, attempt sql.NullInt64
	var observed sql.NullTime
	require.NoError(t, db.QueryRow(`SELECT last_sender_outcome,last_sender_code,last_sender_http_status,
 last_sender_attempt,last_sender_observed_at FROM auth_notification_deliveries WHERE id=$1`, id).
		Scan(&outcome, &code, &status, &attempt, &observed))
	require.False(t, outcome.Valid)
	require.False(t, code.Valid)
	require.False(t, status.Valid)
	require.False(t, attempt.Valid)
	require.False(t, observed.Valid)
}
