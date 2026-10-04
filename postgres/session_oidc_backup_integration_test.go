//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/postgres"
)

// This opt-in native-tools regression is confined to the explicitly owned
// loopback fixture. Connection credentials stay in the inherited environment;
// pg_dump/pg_restore receive only database names and the temporary backup path.
func TestSessionOIDCNativeBackupPreservesStrictState(t *testing.T) {
	if os.Getenv("GOAUTH_TEST_SESSION_BACKUP") != "1" {
		t.Skip("explicit owned-fixture session OIDC backup gate required")
	}
	dsn, err := url.Parse(os.Getenv("GOAUTH_TEST_POSTGRES_DSN"))
	require.NoError(t, err)
	require.Contains(t, []string{"postgres", "postgresql"}, dsn.Scheme)
	require.Equal(t, "127.0.0.1", dsn.Hostname(), "native backup requires an owned loopback fixture")
	require.NotEmpty(t, dsn.Port())
	require.NotNil(t, dsn.User)
	require.Equal(t, dsn.Hostname(), os.Getenv("PGHOST"))
	require.Equal(t, dsn.Port(), os.Getenv("PGPORT"))
	require.Equal(t, dsn.User.Username(), os.Getenv("PGUSER"))
	if hostAddress := os.Getenv("PGHOSTADDR"); hostAddress != "" {
		require.Equal(t, dsn.Hostname(), hostAddress)
	}
	sourceName := strings.TrimPrefix(dsn.Path, "/")
	require.Regexp(t, `^[A-Za-z_][A-Za-z0-9_]*$`, sourceName)
	dumpTool, err := exec.LookPath("pg_dump")
	require.NoError(t, err)
	restoreTool, err := exec.LookPath("pg_restore")
	require.NoError(t, err)

	original, state, current := sessionOIDCFixture(t)
	now := current.CreatedAt
	ctx := authclock.With(t.Context(), func() time.Time { return now })
	request := sessionOIDCRequest(now)
	code := sessionOIDCCode(current)
	completion := oidc.RequestLoginCompletion{
		SessionID: current.Binding.SessionID, CookieDigest: "synthetic-restored-cookie-digest", AuthenticatedAt: now,
	}
	next := current
	next.Token = "synthetic-restored-successor-" + goauth.NewSubjectID().String()
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		return seedSessionOIDCBackup(ctx, state, request, completion, code, current, next, now)
	}))
	before := sessionOIDCBackupSnapshot(t, original.Database())

	restoredName := "oidc_restore_" + strings.ReplaceAll(goauth.NewSubjectID().String(), "-", "")
	_, err = original.Database().ExecContext(t.Context(), "CREATE DATABASE "+pgx.Identifier{restoredName}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := original.Database().ExecContext(context.Background(),
			"DROP DATABASE "+pgx.Identifier{restoredName}.Sanitize()+" WITH (FORCE)")
		require.NoError(t, err)
	})
	backupCtx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	backup := filepath.Join(t.TempDir(), "session-oidc.backup")
	dump := exec.CommandContext(backupCtx, dumpTool, "--dbname="+sourceName,
		"--format=custom", "--no-owner", "--file="+backup)
	output, err := dump.CombinedOutput()
	require.NoError(t, err, "owned strict-state dump: %s", output)
	restore := exec.CommandContext(backupCtx, restoreTool,
		"--dbname="+restoredName, "--no-owner", "--exit-on-error", backup)
	output, err = restore.CombinedOutput()
	require.NoError(t, err, "owned strict-state restore: %s", output)

	restoredURL := *dsn
	restoredURL.Path = "/" + restoredName
	restoredDB, err := sql.Open("pgx", restoredURL.String())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restoredDB.Close()) })
	require.NoError(t, postgres.VerifySchema(t.Context(), restoredDB))
	// runtimeConfig supplies the same deterministic synthetic key rings used by
	// sessionOIDCFixture; no production key or signing-key persistence is needed.
	restored, err := postgres.NewRuntime(postgres.Config{
		DB: restoredDB, Runtime: runtimeConfig(t), NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restored.Close()) })
	restoredState, err := postgres.NewSessionOIDCState(restored)
	require.NoError(t, err)
	require.Equal(t, before, sessionOIDCBackupSnapshot(t, restoredDB), "restore changed strict stored evidence")

	assertSessionOIDCBackupReads(t, restoredState, request, completion, code, current, next)
	assertSessionOIDCBackupGuards(t, restored, restoredState, current, next, before)
	require.NoError(t, restoredState.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		used, err := restoredState.LockRefresh(ctx, current.Token)
		if err != nil {
			return err
		}
		require.Equal(t, current.ClientID, used.ClientID)
		require.NotNil(t, used.ConsumedAt)
		return restoredState.RevokeFamily(ctx, used.FamilyID, oidc.SessionReplay, now)
	}))
	active, err := restoredState.ReadRefresh(ctx, next.Token)
	require.NoError(t, err)
	require.NotNil(t, active.RevokedAt)
	var replayAudits int
	require.NoError(t, restoredDB.QueryRowContext(ctx, `SELECT count(*) FROM auth_security_audit_events
WHERE subject_id=$1 AND event_type='oidc_refresh.replay'`, current.SubjectID).Scan(&replayAudits))
	require.Equal(t, 1, replayAudits)
}

func seedSessionOIDCBackup(
	ctx context.Context, state *postgres.SessionOIDCState, request oidc.SessionRequest,
	completion oidc.RequestLoginCompletion, code oidc.SessionCode, current, next oidc.SessionRefresh, now time.Time,
) error {
	if err := state.SaveRequest(ctx, request); err != nil {
		return err
	}
	if err := state.MarkLoginComplete(ctx, request.Challenge, request.BrowserBinding, completion); err != nil {
		return err
	}
	if _, err := state.ConsumeRequest(ctx, request.Challenge); err != nil {
		return err
	}
	if err := state.SaveCode(ctx, code); err != nil {
		return err
	}
	if err := state.SaveRefresh(ctx, current); err != nil {
		return err
	}
	if _, err := state.ConsumeCode(ctx, code.Code, current.FamilyID, now); err != nil {
		return err
	}
	return state.RotateRefresh(ctx, current, next, now)
}

func sessionOIDCBackupSnapshot(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, entry := range []struct{ name, query string }{
		{"requests", `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY selector),'[]'::jsonb)::text
FROM auth_oidc_authorization_requests r`},
		{"codes", `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY selector),'[]'::jsonb)::text
FROM auth_oidc_authorization_codes r`},
		{"families", `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb)::text
FROM auth_oidc_refresh_families r`},
		{"tokens", `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY selector),'[]'::jsonb)::text
FROM auth_oidc_refresh_tokens r`},
	} {
		var value string
		require.NoError(t, db.QueryRowContext(t.Context(), entry.query).Scan(&value))
		result[entry.name] = value
	}
	return result
}

func assertSessionOIDCBackupReads(
	t *testing.T, state *postgres.SessionOIDCState, request oidc.SessionRequest,
	completion oidc.RequestLoginCompletion, code oidc.SessionCode, current, next oidc.SessionRefresh,
) {
	t.Helper()
	loadedRequest, err := state.ReadRequest(t.Context(), request.Challenge)
	require.NoError(t, err)
	require.NotNil(t, loadedRequest.ConsumedAt)
	require.NotNil(t, loadedRequest.LoginCompletion)
	require.Equal(t, completion.SessionID, loadedRequest.LoginCompletion.SessionID)
	require.Equal(t, completion.CookieDigest, loadedRequest.LoginCompletion.CookieDigest)
	require.True(t, completion.AuthenticatedAt.Equal(loadedRequest.LoginCompletion.AuthenticatedAt))
	loadedCode, err := state.ReadCode(t.Context(), code.Code)
	require.NoError(t, err)
	require.NotNil(t, loadedCode.ConsumedAt)
	require.Equal(t, current.FamilyID, loadedCode.FamilyID)
	require.Equal(t, current.Binding.SessionID, loadedCode.Binding.SessionID)
	require.Equal(t, current.Binding.PolicyStamp, loadedCode.Binding.PolicyStamp)
	require.True(t, current.Binding.AbsoluteExpiresAt.Equal(loadedCode.Binding.AbsoluteExpiresAt))
	consumed, err := state.ReadRefresh(t.Context(), current.Token)
	require.NoError(t, err)
	require.NotNil(t, consumed.ConsumedAt)
	require.Nil(t, consumed.RevokedAt)
	active, err := state.ReadRefresh(t.Context(), next.Token)
	require.NoError(t, err)
	require.Nil(t, active.ConsumedAt)
	require.Nil(t, active.RevokedAt)
	require.Equal(t, current.FamilyID, active.FamilyID)
	require.Equal(t, current.SubjectID, active.SubjectID)
	require.Equal(t, current.SecurityVersion, active.SecurityVersion)
	require.True(t, current.AuthenticatedAt.Equal(active.AuthenticatedAt))
}

func assertSessionOIDCBackupGuards(
	t *testing.T, runtime *postgres.Runtime, state *postgres.SessionOIDCState,
	current, next oidc.SessionRefresh, before map[string]string,
) {
	t.Helper()
	for _, token := range []string{current.Token, next.Token} {
		_, err := runtime.OIDCRefreshTokens().Get(t.Context(), token)
		require.ErrorIs(t, err, oidc.ErrRefreshTokenNotFound)
		require.NoError(t, runtime.OIDCRefreshTokens().Revoke(t.Context(), token, time.Now()))
		unwanted := next.RefreshToken
		unwanted.Token = "synthetic-unwanted-restored-successor-" + goauth.NewSubjectID().String()
		require.ErrorIs(t, runtime.OIDCRefreshTokens().Rotate(t.Context(), token, unwanted, time.Now()),
			oidc.ErrRefreshTokenNotFound)
	}
	for _, statement := range []string{
		`UPDATE auth_oidc_refresh_families SET expires_at=expires_at+interval '1 second'`,
		`UPDATE auth_oidc_refresh_families SET session_id=NULL,authorization_stamp=NULL,absolute_expires_at=NULL`,
		`UPDATE auth_oidc_authorization_requests SET login_cookie_digest='replacement'`,
		`UPDATE auth_oidc_authorization_codes SET consumed_at=NULL`,
		`UPDATE auth_oidc_refresh_tokens SET consumed_at=NULL WHERE consumed_at IS NOT NULL`,
	} {
		_, err := runtime.Database().ExecContext(t.Context(), statement)
		require.Error(t, err)
	}
	require.Equal(t, before, sessionOIDCBackupSnapshot(t, runtime.Database()), "rejected adapters/updates changed state")
	live, err := state.ReadRefresh(t.Context(), next.Token)
	require.NoError(t, err)
	require.Nil(t, live.RevokedAt)
	var audits int
	require.NoError(t, runtime.Database().QueryRowContext(t.Context(),
		`SELECT count(*) FROM auth_security_audit_events WHERE event_type='oidc_refresh.replay'`).Scan(&audits))
	require.Zero(t, audits)
}
