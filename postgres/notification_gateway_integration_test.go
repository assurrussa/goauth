//go:build integration

package postgres //nolint:testpackage // Verify additive schema and lease/payload atomicity against isolated PostgreSQL.

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func gatewayFixtureControlURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return nil, errors.New("invalid gateway fixture control URL")
	}
	ip := net.ParseIP(parsed.Hostname())
	port, portErr := strconv.Atoi(parsed.Port())
	if (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Opaque != "" ||
		ip == nil || !ip.IsLoopback() || portErr != nil || port < 1 || port > 65535 ||
		parsed.RawQuery != "sslmode=disable" || strings.Contains(raw, "#") || parsed.RawPath != "" ||
		!strings.HasPrefix(parsed.Path, "/") || len(strings.Trim(parsed.Path, "/")) == 0 ||
		strings.Count(parsed.Path, "/") != 1 {
		return nil, errors.New("gateway fixture requires explicit loopback PostgreSQL without connection overrides")
	}
	return parsed, nil
}

func gatewayIntegrationDB(t *testing.T) *sql.DB {
	t.Helper()
	raw := os.Getenv("GOAUTH_GATEWAY_TEST_DSN")
	if raw == "" {
		t.Skip("GOAUTH_GATEWAY_TEST_DSN is required for isolated gateway tests")
	}
	parent, err := gatewayFixtureControlURL(raw)
	require.NoError(t, err)
	control, err := sql.Open("pgx", parent.String())
	if err != nil {
		t.Fatal("cannot open gateway fixture control connection")
	}
	name := "goauth_gateway_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	createCtx, cancelCreate := context.WithTimeout(t.Context(), 10*time.Second)
	_, err = control.ExecContext(createCtx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	cancelCreate()
	if err != nil {
		_ = control.Close()
		t.Fatal("cannot create owned gateway fixture database")
	}
	child := *parent
	child.Path, child.RawPath = "/"+name, ""
	var db *sql.DB
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		defer control.Close()
		if db == nil {
			t.Error("owned gateway database retained: child connection unavailable")
			return
		}
		var actual string
		if readErr := db.QueryRowContext(ctx, "SELECT current_database()").Scan(&actual); readErr != nil || actual != name {
			_ = db.Close()
			t.Error("refuse cleanup: owned gateway database identity unavailable or changed")
			return
		}
		require.NoError(t, db.Close())
		_, dropErr := control.ExecContext(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		require.NoError(t, dropErr)
	})
	db, err = sql.Open("pgx", child.String())
	if err != nil {
		t.Fatal("cannot open owned gateway fixture database")
	}
	return db
}

func TestGatewayFixtureControlURLGuardIntegration(t *testing.T) {
	for _, raw := range []string{
		"postgres://fixture@127.0.0.1:16461/postgres?sslmode=disable",
		"postgresql://fixture@[::1]:16461/control?sslmode=disable",
	} {
		_, err := gatewayFixtureControlURL(raw)
		require.NoError(t, err)
	}
	for _, raw := range []string{
		"postgres://fixture@remote.example:16461/postgres?sslmode=disable",
		"postgres://fixture@localhost:16461/postgres?sslmode=disable",
		"postgres://fixture@127.0.0.1/postgres?sslmode=disable",
		"postgres://fixture@127.0.0.1:16461/postgres?sslmode=disable&host=remote.example",
		"postgres://fixture@127.0.0.1:16461/postgres?sslmode=disable&dbname=production",
		"postgres://fixture@127.0.0.1:16461/postgres?sslmode=disable&options=-csearch_path=other",
		"postgres://fixture@127.0.0.1:16461/postgres?sslmode=require",
		"postgres://fixture@127.0.0.1:16461/postgres?sslmode=disable#fragment",
		"postgres://fixture@127.0.0.1:16461/postgres?sslmode=disable#",
		"postgres://fixture@127.0.0.1:16461/other/database?sslmode=disable",
	} {
		_, err := gatewayFixtureControlURL(raw)
		require.Error(t, err)
	}
}

func TestGatewaySchemaOwnershipAndReconciliationIntegration(t *testing.T) {
	ctx := t.Context()
	db := gatewayIntegrationDB(t)
	require.NoError(t, Migrate(ctx, db))
	require.NoError(t, Migrate(ctx, db))
	require.NoError(t, VerifySchema(ctx, db))
	now := time.Now().UTC().Truncate(time.Microsecond)
	subject, err := goauth.ParseSubjectID(uuid.NewString())
	require.NoError(t, err)
	_, err = db.ExecContext(ctx,
		`INSERT INTO auth_subjects(id,status,created_at,updated_at)VALUES($1,'active',$2,$2)`, subject, now)
	require.NoError(t, err)
	store, err := NewStore(db)
	require.NoError(t, err)
	store.notificationProtocol = gatewayTestProtocol
	event := goauth.EncryptedEvent{
		ID: uuid.NewString(), SubjectID: subject, Type: "gateway_test", ValidUntil: now.Add(time.Hour),
		Envelope: goauth.EncryptedEnvelope{
			KeyID: "synthetic", Nonce: []byte{1}, Ciphertext: []byte{2},
			AdditionalData: []byte{3}, CreatedAt: now, DeleteAfter: now.Add(time.Hour),
		},
	}
	require.NoError(t, store.EnqueueEncrypted(ctx, event))
	claim, err := store.claimNotification(ctx, now, time.Minute)
	require.NoError(t, err)
	require.Equal(t, store.notificationProtocol, claim.protocol)
	reserved, err := store.reserveNotificationSend(ctx, claim, 1, now, time.Minute)
	require.NoError(t, err)
	require.True(t, reserved)
	require.NoError(t, store.acceptNotificationQueue(ctx, claim, "receipt-1", now, time.Second))
	var state string
	var ciphertext []byte
	var delivered sql.NullTime
	var attempts int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT state,ciphertext,delivered_at,attempts FROM auth_notification_deliveries
 WHERE id=$1`, event.ID).
		Scan(&state, &ciphertext, &delivered, &attempts))
	require.Equal(t, notificationQueued, state)
	require.Nil(t, ciphertext)
	require.False(t, delivered.Valid)
	require.Equal(t, 1, attempts)
	// A stale lease cannot replace a committed receipt or turn it into delivered.
	require.NoError(t, store.acceptNotificationQueue(ctx, claim, "wrong-receipt", now, time.Second))
	claim, err = store.claimNotification(ctx, now.Add(2*time.Second), time.Minute)
	require.NoError(t, err)
	require.Equal(t, "receipt-1", claim.receiptID)
	require.Empty(t, claim.event.Envelope.Ciphertext)
	sender := &gatewayTestSender{outcome: &goauth.NotificationQueuedError{ReceiptID: "receipt-1"}}
	r := &Runtime{
		store: store, notificationSender: sender,
		notificationNow:    func() time.Time { return now.Add(2 * time.Second) },
		notificationWorker: NotificationWorkerConfig{SendTimeout: time.Second, PollInterval: time.Second, MaxAttempts: 1},
	}
	require.NoError(t, r.deliverNotification(ctx, claim))
	require.Zero(t, sender.sends)
	claim, err = store.claimNotification(ctx, now.Add(4*time.Second), time.Minute)
	require.NoError(t, err)
	sender.outcome = nil
	require.NoError(t, r.deliverNotification(ctx, claim))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT state,delivered_at,attempts FROM auth_notification_deliveries
 WHERE id=$1`, event.ID).
		Scan(&state, &delivered, &attempts))
	require.Equal(t, notificationDelivered, state)
	require.True(t, delivered.Valid)
	require.Equal(t, 1, attempts)
	require.Zero(t, sender.sends)
	rows, err := db.QueryContext(ctx, `SELECT conname,pg_get_constraintdef(oid) FROM pg_constraint
WHERE conrelid='auth_notification_deliveries'::regclass
AND conname IN ('auth_notification_gateway_receipt_check','auth_notification_transport_protocol_check')`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var name, def string
		require.NoError(t, rows.Scan(&name, &def))
		t.Log(name, def)
	}
	require.NoError(t, rows.Err())
}

func TestGatewayUpgradePreservesLegacyAndRejectsDriftIntegration(t *testing.T) {
	ctx := t.Context()
	db := gatewayIntegrationDB(t)
	require.NoError(t, Migrate(ctx, db))
	id, subject := uuid.NewString(), uuid.NewString()
	_, err := db.ExecContext(ctx,
		`INSERT INTO auth_subjects(id,status,created_at,updated_at) VALUES($1,'active',now(),now());`, subject)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO auth_notification_deliveries(id,subject_id,event_type,valid_until,key_id,
nonce,ciphertext,additional_data,created_at,delete_after,next_attempt_at)
 VALUES($1,$2,'legacy',now()+interval '1 hour','synthetic','\x01','\x02','\x03',now(),now()+interval '1 hour',now())`,
		id, subject)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `DROP INDEX auth_notification_gateway_ready_idx;
 ALTER TABLE auth_notification_deliveries DROP CONSTRAINT auth_notification_gateway_receipt_check,
 DROP CONSTRAINT auth_notification_transport_protocol_check,DROP CONSTRAINT auth_notification_deliveries_state_check,
 DROP COLUMN gateway_receipt_id,DROP COLUMN gateway_accepted_at,DROP COLUMN transport_protocol,
 ADD CONSTRAINT auth_notification_deliveries_state_check
 CHECK(state IN ('pending','leased','blocked','delivered','exhausted','expired','cancelled'));
 DELETE FROM goauth_migration_history WHERE version=15;DELETE FROM goauth_schema_version WHERE version=15`)
	require.NoError(t, err)
	require.NoError(t, Migrate(ctx, db))
	require.NoError(t, Migrate(ctx, db))
	require.NoError(t, VerifySchema(ctx, db))
	var protocol, state string
	var payload []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT transport_protocol,state,ciphertext FROM auth_notification_deliveries
 WHERE id=$1`, id).
		Scan(&protocol, &state, &payload))
	require.Empty(t, protocol)
	require.Equal(t, "pending", state)
	require.Equal(t, []byte{2}, payload)
	_, err = db.ExecContext(ctx, `ALTER TABLE auth_notification_deliveries DROP CONSTRAINT auth_notification_gateway_receipt_check,
 ADD CONSTRAINT auth_notification_gateway_receipt_check CHECK(true)`)
	require.NoError(t, err)
	require.ErrorIs(t, VerifySchema(ctx, db), ErrSchemaNeedsMigration)
}

func TestGatewayLateOwnershipCannotOverwriteLeaseOrExpiryIntegration(t *testing.T) {
	for _, mode := range []string{"reclaimed", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			db := gatewayIntegrationDB(t)
			require.NoError(t, Migrate(ctx, db))
			now := time.Now().UTC().Truncate(time.Microsecond)
			event := deadlineEvent(t, uuid.NewString(), now.Add(time.Hour))
			event.Envelope.CreatedAt = now
			_, err := db.ExecContext(ctx,
				`INSERT INTO auth_subjects(id,status,created_at,updated_at)VALUES($1,'active',$2,$2)`, event.SubjectID, now)
			require.NoError(t, err)
			store, err := NewStore(db)
			require.NoError(t, err)
			store.notificationProtocol = gatewayTestProtocol
			require.NoError(t, store.EnqueueEncrypted(ctx, event))
			original, err := store.claimNotification(ctx, now, time.Minute)
			require.NoError(t, err)
			if mode == "reclaimed" {
				current, claimErr := store.claimNotification(ctx, now.Add(2*time.Minute), time.Minute)
				require.NoError(t, claimErr)
				require.NotEqual(t, original.leaseToken, current.leaseToken)
				require.NoError(t, store.acceptNotificationQueue(ctx, original, "stale-receipt", now.Add(2*time.Minute), time.Second))
				var receipt sql.NullString
				var state string
				require.NoError(t, db.QueryRowContext(ctx, `SELECT gateway_receipt_id,state FROM auth_notification_deliveries
 WHERE id=$1`, event.ID).
					Scan(&receipt, &state))
				require.False(t, receipt.Valid)
				require.Equal(t, notificationLeased, state)
				require.NoError(t, store.acceptNotificationQueue(ctx, current, "current-receipt", now.Add(2*time.Minute), time.Second))
				require.NoError(t, db.QueryRowContext(ctx, `SELECT gateway_receipt_id,state FROM auth_notification_deliveries
 WHERE id=$1`, event.ID).
					Scan(&receipt, &state))
				require.Equal(t, "current-receipt", receipt.String)
				require.Equal(t, notificationQueued, state)
			} else {
				runtime := &Runtime{store: store, notificationNow: func() time.Time { return now.Add(2 * time.Hour) }}
				count, expireErr := runtime.ExpireNotifications(ctx, 10)
				require.NoError(t, expireErr)
				require.EqualValues(t, 1, count)
				require.NoError(t, store.acceptNotificationQueue(ctx, original, "late-receipt", now.Add(2*time.Hour), time.Second))
				var receipt sql.NullString
				var state string
				var delivered sql.NullTime
				require.NoError(t, db.QueryRowContext(ctx, `SELECT gateway_receipt_id,state,delivered_at FROM auth_notification_deliveries
 WHERE id=$1`, event.ID).
					Scan(&receipt, &state, &delivered))
				require.False(t, receipt.Valid)
				require.False(t, delivered.Valid)
				require.Equal(t, notificationExpired, state)
			}
		})
	}
}

type legacyGatewayTestSender struct {
	gatewayTestSender
	observe      func(context.Context, goauth.LegacyNotificationReceipt) error
	checksLegacy int
}

func (s *legacyGatewayTestSender) ReconcileLegacyNotification(
	ctx context.Context, receipt goauth.LegacyNotificationReceipt,
) error {
	s.checksLegacy++
	return s.observe(ctx, receipt)
}

func TestGatewayLegacyProviderEvidenceIntegration(t *testing.T) {
	db := gatewayIntegrationDB(t)
	ctx := t.Context()
	require.NoError(t, Migrate(ctx, db))
	for _, name := range []string{
		gatewayLegacyAccepted, "unknown", gatewayLegacyOtherProtocol,
		gatewayLegacyRevoked, gatewayLegacyLateLease, gatewayLegacyDeadline,
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			subject, err := goauth.ParseSubjectID(uuid.NewString())
			require.NoError(t, err)
			_, err = db.ExecContext(ctx,
				`INSERT INTO auth_subjects(id,status,created_at,updated_at)VALUES($1,'active',$2,$2)`, subject, now)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx,
				`INSERT INTO auth_basic_profiles(subject_id,created_at,updated_at) VALUES($1,$2,$2)`, subject, now)
			require.NoError(t, err)
			store, err := NewStore(db)
			require.NoError(t, err)
			event := goauth.EncryptedEvent{
				ID: uuid.NewString(), SubjectID: subject, Type: "legacy_test",
				ValidUntil: now.Add(time.Hour), Envelope: goauth.EncryptedEnvelope{
					KeyID: "unavailable",
					Nonce: []byte{1}, Ciphertext: []byte{2}, AdditionalData: []byte{3}, CreatedAt: now, DeleteAfter: now.Add(time.Hour),
				},
			}
			if name == gatewayLegacyRevoked {
				event.Type = gatewayLegacyPasswordReset
				event.ReferenceID = uuid.NewString()
			}
			if name == gatewayLegacyOtherProtocol {
				store.notificationProtocol = gatewayLegacyOtherProtocol
			}
			require.NoError(t, store.EnqueueEncrypted(ctx, event))
			claim, err := store.claimNotification(ctx, now, time.Minute)
			require.NoError(t, err)
			store.notificationProtocol = gatewayTestProtocol
			sender := &legacyGatewayTestSender{}
			sender.observe = func(_ context.Context, receipt goauth.LegacyNotificationReceipt) error {
				require.Equal(t, event.ID, receipt.ID)
				require.Empty(t, receipt.TransportProtocol)
				require.True(t, event.ValidUntil.Equal(receipt.ValidUntil), "preserve the exact absolute deadline")
				switch name {
				case "unknown":
					return errors.New("no proven provider receipt")
				case gatewayLegacyLateLease:
					_, updateErr := db.ExecContext(ctx,
						`UPDATE auth_notification_deliveries SET lease_token=$2 WHERE id=$1`, event.ID, uuid.NewString())
					require.NoError(t, updateErr)
				case gatewayLegacyDeadline:
					now = event.ValidUntil
				}
				return nil
			}
			runtime := &Runtime{
				store: store, notificationSender: sender, notificationNow: func() time.Time { return now },
				notificationWorker: NotificationWorkerConfig{SendTimeout: time.Second, PollInterval: time.Second, MaxAttempts: 1},
			}
			claim.attempts = 100 // Observation must not reserve a send or decrypt a payload.
			require.NoError(t, runtime.deliverNotification(ctx, claim))
			var state string
			var delivered sql.NullTime
			var payload []byte
			var attempts int
			require.NoError(t, db.QueryRowContext(ctx, `SELECT state,delivered_at,ciphertext,attempts FROM auth_notification_deliveries
WHERE id=$1`, event.ID).Scan(&state, &delivered, &payload, &attempts))
			require.Zero(t, sender.sends)
			require.Zero(t, attempts)
			if name == gatewayLegacyAccepted {
				require.Equal(t, notificationDelivered, state)
				require.True(t, delivered.Valid)
				require.Empty(t, payload)
			} else {
				require.False(t, delivered.Valid)
				require.Equal(t, []byte{2}, payload)
				if name == gatewayLegacyLateLease || name == gatewayLegacyDeadline {
					require.Equal(t, notificationLeased, state)
				} else {
					require.Equal(t, notificationBlocked, state)
				}
			}
			if name == gatewayLegacyRevoked || name == gatewayLegacyOtherProtocol {
				require.Zero(t, sender.checksLegacy)
			} else {
				require.Equal(t, 1, sender.checksLegacy)
			}
			// Keep the next case from reclaiming this intentionally abandoned lease.
			_, err = db.ExecContext(ctx, `DELETE FROM auth_notification_deliveries WHERE id=$1`, event.ID)
			require.NoError(t, err)
		})
	}
}
