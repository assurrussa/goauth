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
	"github.com/assurrussa/goauth/postgres"
)

// This opt-in native-tools gate is limited to an explicitly owned loopback
// fixture. Credentials are inherited in the process environment, not argv.
func TestSubjectRetirementCompatibleBackupPreservesTombstone(t *testing.T) {
	if os.Getenv("GOAUTH_TEST_RETIREMENT_BACKUP") != "1" {
		t.Skip("explicit owned-fixture retirement backup gate required")
	}
	dsn, err := url.Parse(os.Getenv("GOAUTH_TEST_POSTGRES_DSN"))
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1", dsn.Hostname(), "native backup gate requires an owned loopback fixture")
	require.Equal(t, dsn.Hostname(), os.Getenv("PGHOST"))
	require.Equal(t, dsn.Port(), os.Getenv("PGPORT"))
	require.Equal(t, dsn.User.Username(), os.Getenv("PGUSER"))
	dumpTool, err := exec.LookPath("pg_dump")
	require.NoError(t, err)
	restoreTool, err := exec.LookPath("pg_restore")
	require.NoError(t, err)
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	fixture := seedRenameSecurity(t, db, runtime)
	id := fixture.registered.Account.Subject.ID
	_, err = db.Exec(`CREATE TABLE retirement_backup_mapping(source_key text PRIMARY KEY,subject_id uuid NOT NULL)`)
	require.NoError(t, err)
	t.Cleanup(func() { _, err := db.Exec(`DROP TABLE retirement_backup_mapping`); require.NoError(t, err) })
	_, err = db.Exec(`INSERT INTO retirement_backup_mapping VALUES('synthetic-legacy-key',$1)`, id)
	require.NoError(t, err)
	var role int64
	require.NoError(t, db.QueryRow(`INSERT INTO auth_roles(public_id,slug,name)
 VALUES($1,'retirement-backup-role','Retirement backup') RETURNING id`, goauth.NewSubjectID()).Scan(&role))
	t.Cleanup(func() { _, err := db.Exec(`DELETE FROM auth_roles WHERE id=$1`, role); require.NoError(t, err) })
	_, err = db.Exec(`INSERT INTO auth_subject_roles(subject_id,role_id) VALUES($1,$2)`, id, role)
	require.NoError(t, err)
	before, err := runtime.RetireLocalIdentity(t.Context(), retirementRequest(fixture.registered.Account, "SecurityOriginal"))
	require.NoError(t, err)
	snapshot := renameIdentitySnapshot(t, db, id)
	restoredName := "retirement_restore_" + strings.ReplaceAll(goauth.NewSubjectID().String(), "-", "")
	_, err = db.ExecContext(t.Context(), "CREATE DATABASE "+pgx.Identifier{restoredName}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), "DROP DATABASE "+pgx.Identifier{restoredName}.Sanitize()+" WITH (FORCE)")
		require.NoError(t, err)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	backup := filepath.Join(t.TempDir(), "retirement.backup")
	dump := exec.CommandContext(ctx, dumpTool, "--dbname="+strings.TrimPrefix(dsn.Path, "/"),
		"--format=custom", "--no-owner", "--file="+backup)
	output, err := dump.CombinedOutput()
	require.NoError(t, err, "owned fixture dump: %s", output)
	restore := exec.CommandContext(ctx, restoreTool, "--dbname="+restoredName, "--no-owner", "--exit-on-error", backup)
	output, err = restore.CombinedOutput()
	require.NoError(t, err, "owned fixture restore: %s", output)
	restoredURL := *dsn
	restoredURL.Path = "/" + restoredName
	restoredDB, err := sql.Open("pgx", restoredURL.String())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restoredDB.Close()) })
	require.NoError(t, postgres.VerifySchema(t.Context(), restoredDB))
	config := runtimeConfig(t)
	restored, err := postgres.NewRuntime(postgres.Config{DB: restoredDB, Runtime: config, NotificationSender: integrationNotificationSender()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, restored.Close()) })
	after, err := restored.GetSubjectLifecycle(t.Context(), id)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Equal(t, snapshot, renameIdentitySnapshot(t, restoredDB, id), "restore must preserve current credentials, tombstones and revocations")
	var mapped goauth.SubjectID
	require.NoError(t, restoredDB.QueryRow(`SELECT subject_id FROM retirement_backup_mapping WHERE source_key='synthetic-legacy-key'`).Scan(&mapped))
	require.Equal(t, id, mapped)
	assertTrustedPasswordInvalidated(t, restoredDB, id)
	_, err = restored.SetSubjectStatus(t.Context(), id, goauth.SubjectStatusActive)
	require.ErrorIs(t, err, goauth.ErrSubjectRetired)
	_, err = restored.VerifyAccessToken(t.Context(), fixture.registered.Tokens.AccessToken, true)
	require.Error(t, err)
	_, err = restored.Refresh(t.Context(), fixture.registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}
