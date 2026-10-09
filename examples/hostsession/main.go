// Command hostsession demonstrates email-less credentials with host-owned sessions.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

const loginScheme goauth.IdentifierScheme = "host_login"

func main() {
	if err := run(); err != nil {
		// Database errors can contain connection details. Do not print them or secrets.
		fmt.Fprintln(os.Stderr, "host-session example failed; check the isolated database configuration")
		os.Exit(1)
	}
	if _, err := fmt.Fprintln(os.Stdout,
		"Email-less identity authenticated; host membership checked; host session accepted."); err != nil {
		os.Exit(1)
	}
}

func run() error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	// The host opens and owns its one existing pool. Runtime never opens another.
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return demonstrate(ctx, db)
}

func demonstrate(ctx context.Context, db *sql.DB) error {
	// Runtime construction owns its startup timeout; postgres.NewRuntime accepts no caller context.
	runtime, err := newRuntime(db) //nolint:contextcheck // The constructor API cannot inherit ctx.
	if err != nil {
		return err
	}
	defer func() { _ = runtime.Close() }()
	if _, err := db.ExecContext(ctx, hostSchema); err != nil {
		return err
	}
	password, err := randomSecret()
	if err != nil {
		return err
	}
	identifier := goauth.IdentifierInput{Scheme: loginScheme, Value: "demo-" + goauth.NewSubjectID().String()}
	const project = "demo-project"
	// This is privileged synthetic seeding, never an unauthenticated signup API.
	if err := runtime.InOwnedAuthTransaction(ctx, func(txctx context.Context) error {
		account, err := runtime.ProvisionLocalIdentity(txctx, goauth.ProvisionLocalIdentityRequest{
			Identifier: identifier, Password: password,
		})
		if err != nil {
			return err
		}
		q, err := runtime.SQLExecutor(txctx)
		if err != nil {
			return err
		}
		_, err = q.ExecContext(txctx,
			`INSERT INTO example_host_memberships (subject_id, project_id) VALUES ($1, $2)`,
			account.Subject.ID, project)
		return err
	}); err != nil {
		return err
	}
	host := sessionHost{auth: runtime}
	token, err := host.login(ctx, goauth.Credential{Identifier: identifier, Password: password}, project)
	if err != nil {
		return err
	}
	account, err := host.authenticate(ctx, token, project)
	if err != nil {
		return err
	}
	if account.PrimaryEmail != (goauth.Identifier{}) || account.EmailVerified() {
		return errors.New("unexpected email on synthetic identity")
	}
	return nil
}

func newRuntime(db *sql.DB) (*postgres.Runtime, error) {
	keys := make([]goauth.KeyRing, 2)
	for i := range keys {
		material := make([]byte, 32)
		if _, err := rand.Read(material); err != nil {
			return nil, err
		}
		key, err := goauth.NewKeyRing("demo", goauth.Key{ID: "demo", Material: material})
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	// Ephemeral keys and automatic migration are for this disposable demo only.
	return postgres.NewRuntime(postgres.Config{
		DB: db, AutoMigrate: true,
		Runtime: goauth.Config{
			Signing:       goauth.SigningConfig{Issuer: "hostsession-example", Audience: "hostsession-example", Keys: keys[0]},
			TokenHMACKeys: keys[1], NotificationDelivery: goauth.NotificationDeliveryDisabled,
			CredentialVerificationRateLimit: goauth.RateLimitPolicy{Limit: 10, Window: 15 * time.Minute},
			IdentifierResolvers: map[goauth.IdentifierScheme]goauth.IdentifierResolver{
				loginScheme: goauth.IdentifierResolverFunc(normalizeLogin),
			},
		},
	})
}

func normalizeLogin(_ context.Context, input goauth.IdentifierInput) (goauth.IdentifierInput, error) {
	if input.Scheme != loginScheme || len(input.Value) == 0 || len(input.Value) > 64 {
		return goauth.IdentifierInput{}, goauth.ErrInvalidIdentifier
	}
	// Exact, case-sensitive ASCII; do not infer identity from email or profile names.
	for _, c := range input.Value {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return goauth.IdentifierInput{}, goauth.ErrInvalidIdentifier
		}
	}
	return input, nil
}

func randomSecret() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
