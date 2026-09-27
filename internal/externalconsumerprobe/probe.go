package externalconsumerprobe

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	externalconsumer "github.com/assurrussa/goauth/reference/externalconsumer"
)

const (
	DefaultProbeModule = "example.com/goauthprobe"
	DefaultModulePath  = "github.com/assurrussa/goauth"
	LocalModuleVersion = "v0.0.0-local"
)

type Config struct {
	ProbeModule string
	ModulePath  string
	Version     string
	LocalPath   string
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.Version) == "" && strings.TrimSpace(c.LocalPath) == "" {
		return errors.New("external consumer probe: version or local path is required")
	}

	return nil
}

func (c Config) BuildGoMod() (string, error) {
	cfg := c.normalized()
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	var builder strings.Builder
	_, _ = builder.WriteString("module ")
	_, _ = builder.WriteString(cfg.ProbeModule)
	_, _ = builder.WriteString("\n\ngo 1.27.0\n\ntoolchain go1.27.1\n\nrequire ")
	_, _ = builder.WriteString(cfg.ModulePath)
	_, _ = builder.WriteString(" ")
	_, _ = builder.WriteString(cfg.targetVersion())
	_, _ = builder.WriteString("\n")

	if cfg.LocalPath != "" {
		_, _ = builder.WriteString("\nreplace ")
		_, _ = builder.WriteString(cfg.ModulePath)
		_, _ = builder.WriteString(" => ")
		_, _ = builder.WriteString(filepath.Clean(cfg.LocalPath))
		_, _ = builder.WriteString("\n")
	}

	return builder.String(), nil
}

func (c Config) BuildProbeTest() (string, error) {
	cfg := c.normalized()
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	content := strings.ReplaceAll(runnableProbeTest, "GOAUTH_MODULE", cfg.ModulePath)
	for _, pkg := range externalconsumer.SupportedPackages {
		resolved := strings.Replace(pkg, DefaultModulePath, cfg.ModulePath, 1)
		if !strings.Contains(content, strconv.Quote(resolved)) {
			return "", fmt.Errorf("runnable external probe does not exercise supported package %s", pkg)
		}
	}

	return content, nil
}

func (c Config) BuildPostgresProbeTest() (string, error) {
	cfg := c.normalized()
	if err := cfg.Validate(); err != nil {
		return "", err
	}

	return strings.ReplaceAll(postgresProbeTest, "GOAUTH_MODULE", cfg.ModulePath), nil
}

const runnableProbeTest = `package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	basefiber "github.com/gofiber/fiber/v3"
	goredis "github.com/redis/go-redis/v9"

	goauth "GOAUTH_MODULE"
	goauthfiber "GOAUTH_MODULE/fiber"
	"GOAUTH_MODULE/oidc"
	"GOAUTH_MODULE/oidc/provider"
	"GOAUTH_MODULE/oidc/verifier"
	"GOAUTH_MODULE/postgres"
	"GOAUTH_MODULE/rbac"
	goauthredis "GOAUTH_MODULE/redis"
	"GOAUTH_MODULE/testkit"
)

type allowRBACStore struct{}

func (allowRBACStore) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (bool, error) {
	return true, nil
}
func (allowRBACStore) UpsertRole(context.Context, rbac.Role) (rbac.Role, error) {
	return rbac.Role{}, nil
}
func (allowRBACStore) UpsertPermission(context.Context, rbac.Permission) (rbac.Permission, error) {
	return rbac.Permission{}, nil
}
func (allowRBACStore) AssignRole(context.Context, goauth.SubjectID, string) error { return nil }
func (allowRBACStore) SetRolePermissions(context.Context, string, []rbac.PermissionKey) error {
	return nil
}

func TestRuntimeFiberOIDCAndRBACWiring(t *testing.T) {
	fixture, err := testkit.NewRuntime()
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := goauthfiber.New(fixture.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	app := basefiber.New()
	app.Post("/auth/register", adapter.Register)
	request := httptest.NewRequest(
		http.MethodPost,
		"/auth/register",
		strings.NewReader(` + "`" + `{"email":"probe@example.test","password":"Probe-Passphrase-123"}` + "`" + `),
	)
	request.Header.Set(basefiber.HeaderContentType, basefiber.MIMEApplicationJSON)
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d", response.StatusCode)
	}

	permissionService, err := rbac.New(allowRBACStore{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !permissionService.Can(context.Background(), goauth.NewSubjectID(), rbac.MustPermissionKey("probe", "read")) {
		t.Fatal("RBAC adapter did not authorize the probe permission")
	}

	if provider.NewDisabled().Enabled() {
		t.Fatal("disabled OIDC provider is unexpectedly enabled")
	}
	if _, err := verifier.New(verifier.Options{Issuer: "https://auth.example.test", Audience: "probe"}); err != nil {
		t.Fatal(err)
	}
	redisClient := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:6379"})
	defer redisClient.Close()
	if _, err := goauthredis.NewOIDCState(goauthredis.OIDCConfig{Client: redisClient}); err != nil {
		t.Fatal(err)
	}

	_ = oidc.ScopeOpenID
	sender := goauth.NotificationSenderFunc(func(_ context.Context, delivery goauth.NotificationDelivery) error {
		if delivery.ID != "probe" || delivery.Notification.Template != "probe" {
			t.Fatal("managed notification delivery lost its identity or template")
		}
		return nil
	})
	if err := sender.SendNotification(context.Background(), goauth.NotificationDelivery{
		ID: "probe", Notification: goauth.Notification{Template: "probe"},
	}); err != nil {
		t.Fatal(err)
	}
	managed := postgres.Config{
		NotificationSender: sender,
		NotificationWorker: postgres.NotificationWorkerConfig{Workers: 1},
	}
	if managed.NotificationSender == nil {
		t.Fatal("managed notification sender is missing")
	}
	_ = (*postgres.Runtime).RunNotifications
	_ = (*postgres.Runtime).NotificationStats
	_ = postgres.NewOIDCRefreshTokenStore
	_ = (*postgres.Runtime).OIDCProvider
	_ = (*postgres.Runtime).RBAC
}
`

const postgresProbeTest = `package probe

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	basefiber "github.com/gofiber/fiber/v3"
	_ "github.com/jackc/pgx/v5/stdlib"

	goauth "GOAUTH_MODULE"
	goauthfiber "GOAUTH_MODULE/fiber"
	"GOAUTH_MODULE/postgres"
	"GOAUTH_MODULE/rbac"
)

func TestPostgresRuntimeExternalConsumer(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("GOAUTH_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Fatal("GOAUTH_TEST_POSTGRES_DSN is required for the PostgreSQL external consumer probe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("PostgreSQL external consumer probe requires a reachable database: %v", err)
	}

	keyRing := func(name string, fill byte) goauth.KeyRing {
		ring, ringErr := goauth.NewKeyRing(name+"-v1", goauth.Key{
			ID: name + "-v1", Material: bytes.Repeat([]byte{fill}, 32),
		})
		if ringErr != nil {
			t.Fatal(ringErr)
		}
		return ring
	}
	deliveries := make(chan goauth.NotificationDelivery, 1)
	runtime, err := postgres.NewRuntime(postgres.Config{
		DSN: dsn, AutoMigrate: true,
		ConnectionTimeout: 5 * time.Second,
		Runtime: goauth.Config{
			Signing: goauth.SigningConfig{
				Issuer: "https://auth.example.test", Audience: "external-probe", Keys: keyRing("jwt", 1),
			},
			TokenHMACKeys: keyRing("token", 2),
			OutboxAEADKeys: keyRing("outbox", 3),
			URLBuilder: goauth.URLBuilderFunc(func(_ context.Context, token string) (string, error) {
				return "https://app.example.test/reset-password?token=" + url.QueryEscape(token), nil
			}),
			MembershipGate: goauth.MembershipGateFunc(func(context.Context, goauth.Realm, goauth.Account) error {
				return nil
			}),
		},
		NotificationSender: goauth.NotificationSenderFunc(func(_ context.Context, delivery goauth.NotificationDelivery) error {
			select {
			case deliveries <- delivery:
				return nil
			default:
				return context.DeadlineExceeded
			}
		}),
		NotificationWorker: postgres.NotificationWorkerConfig{PollInterval: 10 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := runtime.Close(); closeErr != nil {
			t.Errorf("close PostgreSQL Runtime: %v", closeErr)
		}
	})
	var existingQueue int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*) FROM auth_notification_deliveries WHERE state IN ('pending', 'blocked', 'leased')",
	).Scan(&existingQueue); err != nil {
		t.Fatal(err)
	}
	if existingQueue != 0 {
		t.Fatalf("PostgreSQL external consumer probe requires an idle notification queue; found %d active deliveries", existingQueue)
	}

	workerCtx, stopWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	var workerErr error
	go func() {
		workerErr = runtime.RunNotifications(workerCtx)
		close(workerDone)
	}()

	suffix := strings.ReplaceAll(goauth.NewSubjectID().String(), "-", "")
	email := "probe-" + suffix + "@example.test"
	password := "Probe-Unique-Passphrase-123"
	roleSlug := "probe-" + suffix
	permissionKey := rbac.MustPermissionKey("probe_"+suffix, "read")
	var subjectID goauth.SubjectID
	var roleID, permissionID int64
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		if !subjectID.IsZero() {
			if _, cleanupErr := db.ExecContext(cleanupCtx,
				"DELETE FROM auth_security_audit_events WHERE subject_id = $1", subjectID); cleanupErr != nil {
				t.Errorf("clean probe audit events: %v", cleanupErr)
			}
			if _, cleanupErr := db.ExecContext(cleanupCtx,
				"DELETE FROM auth_subjects WHERE id = $1", subjectID); cleanupErr != nil {
				t.Errorf("clean probe subject: %v", cleanupErr)
			}
		}
		if roleID != 0 {
			if _, cleanupErr := db.ExecContext(cleanupCtx,
				"DELETE FROM auth_roles WHERE id = $1", roleID); cleanupErr != nil {
				t.Errorf("clean probe role: %v", cleanupErr)
			}
		}
		if permissionID != 0 {
			if _, cleanupErr := db.ExecContext(cleanupCtx,
				"DELETE FROM auth_permissions WHERE id = $1", permissionID); cleanupErr != nil {
				t.Errorf("clean probe permission: %v", cleanupErr)
			}
		}
	})
	t.Cleanup(func() {
		stopWorker()
		select {
		case <-workerDone:
			if workerErr != nil {
				t.Errorf("notification worker: %v", workerErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("notification worker did not stop")
		}
	})

	registered, err := runtime.Register(ctx, goauth.RegisterRequest{Email: email, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	subjectID = registered.Account.Subject.ID
	if err := runtime.SendEmailChallenge(ctx, subjectID, goauth.EmailChallengePurposeVerification); err != nil {
		t.Fatal(err)
	}
	var delivery goauth.NotificationDelivery
	select {
	case delivery = <-deliveries:
	case <-workerDone:
		t.Fatalf("notification worker exited before delivery: %v", workerErr)
	case <-ctx.Done():
		t.Fatal("timed out waiting for PostgreSQL notification delivery")
	}
	if delivery.ID == "" || delivery.Notification.Template != "email_challenge" ||
		delivery.Notification.Data["code"] == "" {
		t.Fatalf("invalid email challenge delivery: id=%q template=%q", delivery.ID, delivery.Notification.Template)
	}
	for {
		var state string
		var ciphertextGone bool
		err = db.QueryRowContext(ctx,
			"SELECT state, ciphertext IS NULL FROM auth_notification_deliveries WHERE id = $1 AND subject_id = $2",
			delivery.ID, subjectID).Scan(&state, &ciphertextGone)
		if err != nil {
			t.Fatal(err)
		}
		if state == "delivered" && ciphertextGone {
			break
		}
		select {
		case <-workerDone:
			t.Fatalf("notification worker exited before acknowledging delivery: %v", workerErr)
		case <-ctx.Done():
			t.Fatalf("notification delivery remained in state %q", state)
		case <-time.After(10 * time.Millisecond):
		}
	}
	verified, err := runtime.VerifyEmailChallenge(ctx, subjectID,
		goauth.EmailChallengePurposeVerification, delivery.Notification.Data["code"])
	if err != nil || !verified.EmailVerified() {
		t.Fatalf("PostgreSQL email verification failed: verified=%v err=%v", verified.EmailVerified(), err)
	}

	loggedIn, err := runtime.Login(ctx, goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: email},
			Password: password,
		}, Realm: goauth.RealmUser,
	})
	if err != nil {
		t.Fatal(err)
	}
	if loggedIn.Account.Subject.ID != subjectID || loggedIn.Tokens.AccessToken == "" ||
		loggedIn.Tokens.Session.Scope != goauth.SessionScopeAuthenticated {
		t.Fatal("PostgreSQL login did not return an authenticated session")
	}
	adapter, err := goauthfiber.New(runtime)
	if err != nil {
		t.Fatal(err)
	}
	app := basefiber.New()
	app.Get("/protected", adapter.RequireRealm(goauth.RealmUser,
		goauthfiber.RealmMiddlewareOptions{Introspect: true}), func(c basefiber.Ctx) error {
		return c.SendStatus(http.StatusNoContent)
	})
	protectedRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodGet, "/protected", nil)
		request.Header.Set(basefiber.HeaderAuthorization, "Bearer "+loggedIn.Tokens.AccessToken)
		return request
	}
	response, err := app.Test(protectedRequest())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("introspected protected route status = %d", response.StatusCode)
	}

	permissions, err := runtime.RBAC(nil)
	if err != nil {
		t.Fatal(err)
	}
	if permissions.Can(ctx, subjectID, permissionKey) {
		t.Fatal("new subject unexpectedly has the probe permission")
	}
	permission, err := permissions.UpsertPermission(ctx, rbac.Permission{Key: permissionKey})
	if err != nil {
		t.Fatal(err)
	}
	permissionID = permission.ID
	role, err := permissions.UpsertRole(ctx, rbac.Role{Slug: roleSlug, Name: "External consumer probe"})
	if err != nil {
		t.Fatal(err)
	}
	roleID = role.ID
	if err := permissions.SetRolePermissions(ctx, roleSlug, []rbac.PermissionKey{permissionKey}); err != nil {
		t.Fatal(err)
	}
	if err := permissions.AssignRole(ctx, subjectID, roleSlug); err != nil {
		t.Fatal(err)
	}
	if !permissions.Can(ctx, subjectID, permissionKey) {
		t.Fatal("PostgreSQL RBAC did not authorize the assigned permission")
	}
	if err := runtime.Logout(ctx, subjectID, loggedIn.Tokens.Session.ID); err != nil {
		t.Fatal(err)
	}
	response, err = app.Test(protectedRequest())
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked protected route status = %d", response.StatusCode)
	}
	if err := runtime.RequestPasswordReset(ctx, email); err != nil {
		t.Fatal(err)
	}
	var resetDelivery goauth.NotificationDelivery
	select {
	case resetDelivery = <-deliveries:
	case <-workerDone:
		t.Fatalf("notification worker exited before reset delivery: %v", workerErr)
	case <-ctx.Done():
		t.Fatal("timed out waiting for PostgreSQL password reset delivery")
	}
	resetURL, err := url.Parse(resetDelivery.Notification.Data["reset_url"])
	if err != nil {
		t.Fatal(err)
	}
	newPassword := "Probe-Replacement-Passphrase-456"
	if err := runtime.ResetPassword(ctx, resetURL.Query().Get("token"), newPassword); err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Login(ctx, goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: email},
			Password: newPassword,
		}, Realm: goauth.RealmUser,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Cleanup(ctx, postgres.CleanupPolicy{}); err != nil {
		t.Fatal(err)
	}
}
`

func (c Config) normalized() Config {
	cfg := c
	cfg.ProbeModule = strings.TrimSpace(cfg.ProbeModule)
	cfg.ModulePath = strings.TrimSpace(cfg.ModulePath)
	cfg.Version = strings.TrimSpace(cfg.Version)
	cfg.LocalPath = strings.TrimSpace(cfg.LocalPath)

	if cfg.ProbeModule == "" {
		cfg.ProbeModule = DefaultProbeModule
	}
	if cfg.ModulePath == "" {
		cfg.ModulePath = DefaultModulePath
	}

	return cfg
}

func (c Config) targetVersion() string {
	if strings.TrimSpace(c.Version) != "" {
		return strings.TrimSpace(c.Version)
	}

	return LocalModuleVersion
}
