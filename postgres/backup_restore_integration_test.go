//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
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
	port := os.Getenv("GOAUTH_TEST_POSTGRES_PORT")
	if port == "" {
		port = "55432"
	}
	project := os.Getenv("GOAUTH_TEST_COMPOSE_PROJECT")
	if project == "" {
		project = backupFixtureProject
	}
	u, err := backupFixtureURL(os.Getenv("GOAUTH_TEST_POSTGRES_DSN"), port, project)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ids, err := exec.CommandContext(ctx, "docker", "compose", "-f", "../compose.integration.yml", "-p", project, "ps", "--status", "running", "-q", "postgres").Output()
	require.NoError(t, err, "resolve disposable Compose fixture")
	containerIDs := strings.Fields(string(ids))
	require.Len(t, containerIDs, 1, "backup fixture requires exactly one running postgres container")
	containerID := containerIDs[0]
	inspection, err := exec.CommandContext(ctx, "docker", "inspect", containerID).Output()
	require.NoError(t, err, "inspect disposable Compose fixture")
	require.NoError(t, validateBackupContainer(inspection, containerID, project, port))
	admin, err := sql.Open("pgx", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	// A remote Docker context must not make the loopback DSN target another server.
	var serverID string
	require.NoError(t, admin.QueryRowContext(ctx, "SELECT system_identifier::text FROM pg_control_system()").Scan(&serverID))
	fixtureID, err := exec.CommandContext(ctx, "docker", "exec", containerID, "psql", "--username=goauth", "--dbname=goauth_integration", "-At", "-c", "SELECT system_identifier::text FROM pg_control_system()").Output()
	require.NoError(t, err, "read disposable fixture server identity")
	require.NotEmpty(t, serverID)
	require.Equal(t, serverID, strings.TrimSpace(string(fixtureID)), "DSN and inspected container must identify the same PostgreSQL server")
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
	dump := exec.CommandContext(ctx, "docker", "exec", "-i", containerID, "pg_dump", "--username=goauth", "--dbname="+sourceName, "--format=custom", "--no-owner")
	backup, err := dump.Output()
	require.NoError(t, err, "pg_dump must succeed")
	require.NotEmpty(t, backup)
	restore := exec.CommandContext(ctx, "docker", "exec", "-i", containerID, "pg_restore", "--username=goauth", "--dbname="+restoredName, "--no-owner", "--exit-on-error")
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
