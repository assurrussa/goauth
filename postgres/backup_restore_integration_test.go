//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

// TestPostgresBackupRestore uses only the disposable Compose project. Invoking
// its gate requires the tools; it must not turn missing backup tooling into a pass.
func TestPostgresBackupRestore(t *testing.T) {
	if os.Getenv("GOAUTH_TEST_BACKUP_RESTORE") != "1" {
		t.Skip("explicit backup-restore gate required")
	}
	u, err := url.Parse(os.Getenv("GOAUTH_TEST_POSTGRES_DSN"))
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:55432", u.Host, "backup fixture must use the disposable Compose project")
	require.NotNil(t, u.User)
	require.Equal(t, "goauth", u.User.Username())
	admin, err := sql.Open("pgx", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	sourceName := "goauth_backup_" + strings.ReplaceAll(goauth.NewSubjectID().String(), "-", "")
	restoredName := sourceName + "_restored"
	for _, name := range []string{sourceName, restoredName} {
		_, err = admin.ExecContext(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := admin.ExecContext(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
			require.NoError(t, err)
		})
	}
	sourceURL := *u
	sourceURL.Path = "/" + sourceName
	cfg := runtimeConfig(t)
	cfg.EventSink = nil
	sender := goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error { return nil })
	original, err := postgres.NewRuntime(postgres.Config{DSN: sourceURL.String(), AutoMigrate: true, Runtime: cfg, NotificationSender: sender})
	require.NoError(t, err)
	// Close owned connections before the dump; cleanup remains safe on failure.
	t.Cleanup(func() { _ = original.Close() })
	account, err := original.ProvisionTrustedLocalAccount(ctx, goauth.RegisterRequest{Email: "backup@example.test", Password: "Backup-Unique-Passphrase-123"})
	require.NoError(t, err)
	login, err := original.Login(ctx, login("backup@example.test", "Backup-Unique-Passphrase-123"))
	require.NoError(t, err)
	require.NoError(t, original.RequestPasswordReset(ctx, account.PrimaryEmail.DisplayValue))
	require.NoError(t, original.Close())
	dump := exec.CommandContext(ctx, "docker", "compose", "-f", "../compose.integration.yml", "-p", "goauth-v02-integration", "exec", "-T", "postgres", "pg_dump", "--username=goauth", "--dbname="+sourceName, "--format=custom", "--no-owner")
	backup, err := dump.Output()
	require.NoError(t, err, "pg_dump must succeed")
	require.NotEmpty(t, backup)
	restore := exec.CommandContext(ctx, "docker", "compose", "-f", "../compose.integration.yml", "-p", "goauth-v02-integration", "exec", "-T", "postgres", "pg_restore", "--username=goauth", "--dbname="+restoredName, "--no-owner", "--exit-on-error")
	restore.Stdin = bytes.NewReader(backup)
	require.NoError(t, restore.Run(), "pg_restore must succeed")
	restoredURL := *u
	restoredURL.Path = "/" + restoredName
	restoredDB, err := sql.Open("pgx", restoredURL.String())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restoredDB.Close()) })
	require.NoError(t, postgres.VerifySchema(ctx, restoredDB))
	deliveries := make(chan goauth.NotificationDelivery, 1)
	restored, err := postgres.NewRuntime(postgres.Config{DB: restoredDB, Runtime: cfg, NotificationSender: goauth.NotificationSenderFunc(func(_ context.Context, d goauth.NotificationDelivery) error { deliveries <- d; return nil }), NotificationWorker: postgres.NotificationWorkerConfig{PollInterval: 10 * time.Millisecond}})
	require.NoError(t, err)
	authenticated, err := restored.AuthenticateSession(ctx, login.Tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, account.Subject.ID, authenticated.SubjectID)
	workerCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- restored.RunNotifications(workerCtx) }()
	select {
	case d := <-deliveries:
		require.NotEmpty(t, d.ID)
		require.Equal(t, account.PrimaryEmail.DisplayValue, d.Notification.To)
	case <-ctx.Done():
		t.Fatal("restored encrypted delivery did not decrypt/send with retained keys")
	}
	stop()
	require.NoError(t, <-done)
	_, err = restored.LogoutAll(ctx, account.Subject.ID)
	require.NoError(t, err)
	_, err = restored.AuthenticateSession(ctx, login.Tokens.AccessToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}
