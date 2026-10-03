//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

// Optional frozen-source probes compile real pre-retirement binaries in a
// temporary consumer, without modifying their checkouts or downloading modules.
// Migration source hashes pin the guards, so a moving checkout cannot silently
// turn the old-binary refusal test into a current-binary test.
func TestSubjectRetirementOldBinaryRefusesStartup(t *testing.T) {
	for _, previous := range []struct{ name, variable, checksum string }{
		{"schema-v4", "GOAUTH_TEST_V4_SOURCE_DIR", "13fb383e73eab6d8f0180ea68eb0d4548a47656f8a3eb34d9cf45a5de5ef16c1"},
		{"schema-v5", "GOAUTH_TEST_V5_SOURCE_DIR", "204504526ccc9334d0206692837872c6cb5080e585ce5fe797f016bdd55987f0"},
	} {
		t.Run(previous.name, func(t *testing.T) {
			source := os.Getenv(previous.variable)
			if source == "" {
				t.Skip(previous.variable + " is not configured")
			}
			testRetirementOldBinary(t, source, previous.checksum)
		})
	}
}

func testRetirementOldBinary(t *testing.T, source, expectedChecksum string) {
	t.Helper()
	absolute, err := filepath.Abs(source)
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(absolute, "postgres", "migrate.go"))
	require.NoError(t, err)
	checksum := sha256.Sum256(data)
	require.Equal(t, expectedChecksum, hex.EncodeToString(checksum[:]), "old-binary source guard changed")
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	seedPreRetirementSchema(t, db, 6)
	_, err = db.ExecContext(t.Context(), `UPDATE auth_subjects SET retired_at=updated_at WHERE status='disabled'`)
	require.NoError(t, err)
	before := retirementMigrationSnapshot(t, db, 6)

	consumer := t.TempDir()
	module := fmt.Sprintf("module retirement-rollback-probe\n\ngo 1.27.0\n\n"+
		"require github.com/assurrussa/goauth v0.0.0\n\nreplace github.com/assurrussa/goauth => %q\n", absolute)
	require.NoError(t, os.WriteFile(filepath.Join(consumer, "go.mod"), []byte(module), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(consumer, "main.go"), []byte(retirementOldBinaryProbe), 0o600))
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "run", "-mod=mod", ".")
	command.Dir = consumer
	command.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off")
	output, err := command.CombinedOutput()
	require.NoError(t, err, "old-binary startup probe: %s", output)
	require.Contains(t, string(output), "older-schema startup refused newer schema in both modes")
	require.Equal(t, before, retirementMigrationSnapshot(t, db, 6), "rejected rollback must preserve tombstones and all state")
}

const retirementOldBinaryProbe = `package main

import (
    "bytes"
    "context"
    "database/sql"
    "errors"
    "fmt"
    "os"

    "github.com/assurrussa/goauth"
    "github.com/assurrussa/goauth/postgres"
)

func keyRing(id string, fill byte) goauth.KeyRing {
    keys, err := goauth.NewKeyRing(id, goauth.Key{ID: id, Material: bytes.Repeat([]byte{fill}, 32)})
    if err != nil { panic(err) }
    return keys
}

func main() {
    db, err := sql.Open("pgx", os.Getenv("GOAUTH_TEST_POSTGRES_DSN"))
    if err != nil { panic(err) }
    defer db.Close()
    for _, auto := range []bool{false, true} {
        runtime, err := postgres.NewRuntime(postgres.Config{
            DB: db, AutoMigrate: auto,
            Runtime: goauth.Config{
                NotificationDelivery: goauth.NotificationDeliveryDisabled,
                Signing: goauth.SigningConfig{Issuer:"https://rollback.example.test",Audience:"rollback",Keys:keyRing("sign", 1)},
                TokenHMACKeys: keyRing("token", 2),
            },
        })
        if runtime != nil || !errors.Is(err, postgres.ErrFutureSchema) {
            panic(fmt.Sprintf("auto=%v runtime=%v expected ErrFutureSchema, got %v", auto, runtime, err))
        }
    }
    if err := postgres.VerifySchema(context.Background(), db); !errors.Is(err, postgres.ErrFutureSchema) {
        panic(fmt.Sprintf("VerifySchema expected ErrFutureSchema, got %v", err))
    }
    if err := postgres.Migrate(context.Background(), db); !errors.Is(err, postgres.ErrFutureSchema) {
        panic(fmt.Sprintf("Migrate expected ErrFutureSchema, got %v", err))
    }
    fmt.Println("older-schema startup refused newer schema in both modes")
}
`
