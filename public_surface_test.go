package goauth_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/assurrussa/goauth"
	goauthfiber "github.com/assurrussa/goauth/fiber"
	goauthhttp "github.com/assurrussa/goauth/nethttp"
	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/oidc/provider"
	"github.com/assurrussa/goauth/oidc/verifier"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/rbac"
	"github.com/assurrussa/goauth/redis"
	externalconsumer "github.com/assurrussa/goauth/reference/externalconsumer"
	"github.com/assurrussa/goauth/testkit"
)

func TestSupportedPublicSurfaceCompiles(t *testing.T) {
	t.Helper()

	var authTransaction goauth.AuthTransaction = (*postgres.Store)(nil)
	_ = authTransaction
	_ = (*goauth.Runtime).VerifyJWT
	_ = (*goauth.Runtime).AuthenticateSession
	_ = goauth.ErrOperationOutcomeUnknown
	_ = goauth.ErrPasswordHashOverloaded
	_ = goauth.ErrPasswordVerificationUnavailable
	_ = goauth.DefaultMaxConcurrentPasswordHashes
	_ = goauth.Config{MaxConcurrentPasswordHashes: 4}
	_ = goauth.Config{AutoLinkVerifiedEmailIssuers: []string{}, AuthTransaction: authTransaction}
	_ = goauth.PasswordPolicy{DisableBlocklist: true}
	_ = goauthhttp.New
	_ = goauthhttp.RealmMiddlewareOptions{OfflineJWT: true}
	_ = goauthhttp.AuthContext
	_ = goauthhttp.WriteError
	_ = verifier.Options{DiscoveryURL: "", HTTPTimeout: 0, MaxResponseBytes: 0, AllowInsecureHTTP: false}
	_ = verifier.Options{AccessTokenProfile: verifier.AccessTokenProfileZITADEL}
	_ = verifier.AccessTokenProfileGoAuth
	_ = verifier.AccessTokenProfile("")
	_ = goauth.NewRuntime
	_ = goauth.NewKeyRing
	_ = goauth.NewArgon2idHasher
	_ = goauth.NewSubjectID
	_ = goauth.ParseSubjectID
	_ = goauth.DefaultPasswordPolicy
	_ = goauth.Config{}
	_ = goauth.Config{ManagedNotificationDelivery: true}
	_ = goauth.Subject{}
	_ = goauth.Identifier{}
	_ = goauth.BasicProfile{}
	_ = goauth.Account{}
	_ = goauth.Credential{}
	_ = goauth.RealmUser
	_ = goauth.RealmAdmin
	_ = goauth.MaxAccessTokenTTL
	_ = goauth.ErrReservedAccessTokenClaim
	_ = goauth.ChangePasswordRequest{}
	_ = goauth.PendingEmailChange{}
	_ = goauth.EmailChangeRecord{}
	_ = goauth.PasswordResetRecord{ExpectedNormalizedEmail: "", ExpectedSecurityVersion: 1}
	_ = goauth.EmailChallengeRecord{ExpectedNormalizedEmail: "", ExpectedSecurityVersion: 1}
	_ = goauth.ErrPasswordChangeConflict
	_ = goauth.ErrEmailChangeNotFound
	_ = goauth.NotificationDelivery{}
	_ = goauth.NotificationSenderFunc(nil)
	var sender goauth.NotificationSender = goauth.NotificationSenderFunc(nil)
	_ = sender
	var notificationTransaction goauth.NotificationTransaction = (*postgres.Store)(nil)
	_ = notificationTransaction
	_ = (*goauth.Runtime).ProvisionTrustedLocalAccount
	_ = (*goauth.Runtime).VerifyCredential
	_ = (*goauth.Runtime).GetAccount
	_ = (*goauth.Runtime).FindAccount
	_ = (*goauth.Runtime).UpdateBasicProfile
	_ = (*goauth.Runtime).ChangePassword
	_ = (*goauth.Runtime).RequestEmailChange
	_ = (*goauth.Runtime).PendingEmailChange
	_ = (*goauth.Runtime).ConfirmEmailChange
	_ = (*goauth.Runtime).Logout
	_ = (*goauth.Runtime).LogoutAll

	_ = postgres.NewRuntime
	_ = postgres.NewRBAC
	_ = postgres.NewOIDCRefreshTokenStore
	_ = postgres.Migrate
	_ = postgres.Down
	_ = postgres.ResetConfirmation("")
	_ = postgres.ConfirmResetAuthState
	_ = postgres.ErrLegacySchemaRequiresReset
	_ = postgres.Config{
		NotificationSender: goauth.NotificationSenderFunc(nil),
		NotificationWorker: postgres.NotificationWorkerConfig{},
	}
	_ = postgres.NotificationQueueStats{}
	_ = postgres.NotificationBlockedEvent{}
	_ = postgres.NotificationWorkerConfig{OnBlocked: func(postgres.NotificationBlockedEvent) {}}
	_ = (*postgres.Runtime).RunNotifications
	_ = (*postgres.Runtime).NotificationStats
	_ = (*postgres.Runtime).OIDCProvider
	_ = (*postgres.Runtime).OIDCRefreshTokens
	_ = (*postgres.Runtime).RBAC

	_ = redis.NewOIDCState
	_ = redis.OIDCConfig{}

	_ = goauthfiber.New
	_ = goauthfiber.WriteError
	_ = goauthfiber.AuthContext
	_ = goauthfiber.RealmMiddlewareOptions{}

	_ = oidc.ScopeOpenID
	_ = oidc.AuthorizationRequest{}
	_ = oidc.ErrRefreshTokenReplay
	_ = provider.New
	_ = provider.NewDisabled
	_ = verifier.New

	_ = rbac.New
	_ = rbac.NewPermissionKey
	_ = rbac.Permission{}
	_ = rbac.Role{}
	_ = rbac.RoleFilter{}
	_ = rbac.PermissionFilter{}
	_ = rbac.Snapshot{}
	_ = (*rbac.Service).Roles
	_ = (*rbac.Service).Role
	_ = (*rbac.Service).CreateRole
	_ = (*rbac.Service).UpdateRole
	_ = (*rbac.Service).DeleteRole
	_ = (*rbac.Service).Permissions
	_ = (*rbac.Service).RolePermissions
	_ = (*rbac.Service).ReplaceRolePermissions
	_ = (*rbac.Service).ReplaceSubjectRoles
	_ = (*rbac.Service).SubjectRoles
	_ = (*rbac.Service).Snapshot

	_ = testkit.NewRuntime
	_ = testkit.NewStore
	_ = testkit.DecryptNotification
	_ = externalconsumer.SupportedPackageCount
}

func TestPublicSurfaceImportsAreSupportedExternalPackages(t *testing.T) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", "public_surface_test.go"), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse public surface imports: %v", err)
	}

	supported := map[string]struct{}{}
	for _, pkg := range externalconsumer.SupportedPackages {
		supported[pkg] = struct{}{}
	}

	var missing []string
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			t.Fatalf("unquote import path: %v", err)
		}
		if path == "github.com/assurrussa/goauth/reference/externalconsumer" {
			continue
		}
		if path != "github.com/assurrussa/goauth" &&
			!strings.HasPrefix(path, "github.com/assurrussa/goauth/") {
			continue
		}
		if _, ok := supported[path]; !ok {
			missing = append(missing, path)
		}
	}

	slices.Sort(missing)
	if len(missing) != 0 {
		t.Fatalf("public surface packages missing from external manifest: %v", missing)
	}
}

func TestManifestDoesNotPublishLegacyImplementationPackages(t *testing.T) {
	t.Helper()

	legacyPrefixes := []string{
		"github.com/assurrussa/goauth/core",
		"github.com/assurrussa/goauth/domain/",
		"github.com/assurrussa/goauth/http/",
		"github.com/assurrussa/goauth/infrastructure/",
		"github.com/assurrussa/goauth/integration/",
		"github.com/assurrussa/goauth/local/",
		"github.com/assurrussa/goauth/migrations",
		"github.com/assurrussa/goauth/service/",
		"github.com/assurrussa/goauth/session/",
		"github.com/assurrussa/goauth/storage/",
		"github.com/assurrussa/goauth/usecases/",
	}
	var offenders []string
	for _, pkg := range externalconsumer.SupportedPackages {
		for _, prefix := range legacyPrefixes {
			if strings.HasPrefix(pkg, prefix) {
				offenders = append(offenders, pkg)
			}
		}
	}
	if len(offenders) != 0 {
		t.Fatalf("legacy implementation packages are release-visible: %v", offenders)
	}
}

func TestRetiredImplementationPackagesAreAbsent(t *testing.T) {
	t.Helper()

	for _, directory := range []string{
		"core",
		"domain",
		"http",
		"infrastructure",
		"integration",
		"local",
		"migrations",
		"service",
		"session",
		"shared",
		"sso",
		"storage",
		"usecases",
	} {
		_, err := os.Stat(directory)
		if !os.IsNotExist(err) {
			t.Fatalf("retired implementation directory %q must be absent", directory)
		}
	}

	if _, err := os.Stat(filepath.Join("internal", "legacy")); !os.IsNotExist(err) {
		t.Fatalf("internal legacy implementation must be absent: %v", err)
	}
}

func TestReleaseDocsDoNotContainMachineLocalPaths(t *testing.T) {
	t.Helper()

	for _, filename := range []string{
		"README.md",
		"RELEASING.md",
		"AUTH_INVARIANTS.md",
		"docs/project-contract.md",
		"docs/public-surface.md",
		"docs/release-verification.md",
		"docs/v0.2-runtime.md",
	} {
		content, err := os.ReadFile(filename)
		if err != nil {
			t.Fatalf("read %s: %v", filename, err)
		}
		if strings.Contains(string(content), "/Users/") || strings.Contains(string(content), "~/") {
			t.Fatalf("%s contains a machine-local path", filename)
		}
	}
}
