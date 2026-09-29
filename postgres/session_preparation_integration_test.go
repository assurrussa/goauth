//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

const sessionPreparationPassword = "Integration-Unique-Passphrase-1" //nolint:gosec // Isolated fixture credential.

func TestPostgresSessionIssuanceExpiryRollback(t *testing.T) {
	db := integrationDB(t)
	for _, tc := range []struct {
		name       string
		fraction   time.Duration
		accessTTL  time.Duration
		sessionTTL time.Duration
		delay      time.Duration
	}{
		{"access expiry", 0, time.Second, time.Minute, time.Second},
		{"session expiry", 0, time.Minute, time.Second, time.Second},
		{"JWT second precision", 250 * time.Millisecond, time.Second, time.Minute, 800 * time.Millisecond},
	} {
		for _, operation := range []string{"register", "login", "external login"} {
			t.Run(tc.name+"/"+operation, func(t *testing.T) {
				resetSchema(t, db)
				require.NoError(t, postgres.Migrate(t.Context(), db))
				now := time.Now().UTC().Truncate(time.Second).Add(tc.fraction)
				var slow bool
				config := runtimeConfig(t)
				config.Now = func() time.Time { return now }
				config.AccessTTL = tc.accessTTL
				config.SessionTTL = tc.sessionTTL
				config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
					context.Context, goauth.Realm, goauth.Account, map[string]any,
				) error {
					if slow {
						now = now.Add(tc.delay)
					}
					return nil
				})
				runtime, err := postgres.NewRuntime(postgres.Config{
					DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
				})
				require.NoError(t, err)
				const email = "pg.expired.session@example.test"
				baseline := 0
				if operation == "login" {
					register(t, runtime, email)
					baseline = 1
				}
				external := goauth.ExternalIdentity{
					Issuer: "https://session.idp.example.test", Subject: "expired-session", Email: email, EmailVerified: true,
				}
				attempt := func() (goauth.TokenPair, error) {
					switch operation {
					case "register":
						result, err := runtime.Register(t.Context(), goauth.RegisterRequest{Email: email, Password: sessionPreparationPassword})
						return result.Tokens, err
					case "login":
						result, err := runtime.Login(t.Context(), goauth.LoginRequest{Credential: goauth.Credential{
							Identifier: goauth.IdentifierInput{Value: email}, Password: sessionPreparationPassword,
						}})
						return result.Tokens, err
					default:
						result, err := runtime.LoginExternal(t.Context(), goauth.ExternalLoginRequest{Identity: external})
						return result.Tokens, err
					}
				}
				slow = true
				tokens, err := attempt()
				require.ErrorIs(t, err, goauth.ErrExpiredToken)
				require.Empty(t, tokens.AccessToken)
				require.Empty(t, tokens.RefreshToken)
				var subjects, credentials, identifiers, profiles, sessions, families, refresh, links, events int
				require.NoError(t, db.QueryRowContext(t.Context(), `SELECT
    (SELECT count(*) FROM auth_subjects),
    (SELECT count(*) FROM auth_local_credentials),
    (SELECT count(*) FROM auth_identifiers),
    (SELECT count(*) FROM auth_basic_profiles),
    (SELECT count(*) FROM auth_sessions),
    (SELECT count(*) FROM auth_refresh_families),
    (SELECT count(*) FROM auth_refresh_tokens),
    (SELECT count(*) FROM auth_identity_links),
    (SELECT count(*) FROM auth_notification_deliveries)`).Scan(
					&subjects, &credentials, &identifiers, &profiles, &sessions, &families, &refresh, &links, &events,
				))
				for table, count := range map[string]int{
					"subjects": subjects, "credentials": credentials, "identifiers": identifiers,
					"profiles": profiles, "sessions": sessions, "families": families, "refresh": refresh,
				} {
					require.Equal(t, baseline, count, table+" must be unchanged after failed issuance")
				}
				require.Zero(t, links)
				require.Zero(t, events)
				slow = false
				tokens, err = attempt()
				require.NoError(t, err, "same identifier must remain usable after rollback")
				_, err = runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
				require.NoError(t, err)
				_, err = runtime.Refresh(t.Context(), tokens.RefreshToken)
				require.NoError(t, err)
			})
		}
	}
}

func TestPostgresSessionWriteLatencyRollsBackRegistration(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	require.NoError(t, func() error {
		_, err := db.ExecContext(t.Context(), `
CREATE FUNCTION goauth_test_delay_session_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_sleep(1.1);
    RETURN NEW;
END;
$$;
CREATE TRIGGER goauth_test_delay_session BEFORE INSERT ON auth_sessions
FOR EACH ROW EXECUTE FUNCTION goauth_test_delay_session_insert();`)
		return err
	}())
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), `
DROP TRIGGER IF EXISTS goauth_test_delay_session ON auth_sessions;
DROP FUNCTION IF EXISTS goauth_test_delay_session_insert();`)
		require.NoError(t, err)
	})
	config := runtimeConfig(t)
	config.AccessTTL = time.Second
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	request := goauth.RegisterRequest{Email: "pg.slow.session@example.test", Password: sessionPreparationPassword}
	result, err := runtime.Register(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrExpiredToken)
	require.Empty(t, result.Tokens.AccessToken)
	var subjects, sessions, families, tokens int
	require.NoError(t, db.QueryRowContext(t.Context(), `SELECT
    (SELECT count(*) FROM auth_subjects),
    (SELECT count(*) FROM auth_sessions),
    (SELECT count(*) FROM auth_refresh_families),
    (SELECT count(*) FROM auth_refresh_tokens)`).Scan(&subjects, &sessions, &families, &tokens))
	require.Zero(t, subjects)
	require.Zero(t, sessions)
	require.Zero(t, families)
	require.Zero(t, tokens)
	_, err = db.ExecContext(t.Context(), `DROP TRIGGER goauth_test_delay_session ON auth_sessions`)
	require.NoError(t, err)
	config.AccessTTL = time.Minute
	runtime, err = postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: config, NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	result, err = runtime.Register(t.Context(), request)
	require.NoError(t, err)
	_, err = runtime.AuthenticateSession(t.Context(), result.Tokens.AccessToken)
	require.NoError(t, err)
}
