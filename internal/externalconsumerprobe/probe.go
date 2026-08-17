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
	_, _ = builder.WriteString("\n\ngo 1.26.6\n\ntoolchain go1.26.6\n\nrequire ")
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
	_ = postgres.Config{}
	_ = postgres.NewOIDCRefreshTokenStore
	_ = (*postgres.Runtime).OIDCProvider
	_ = (*postgres.Runtime).RBAC
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
