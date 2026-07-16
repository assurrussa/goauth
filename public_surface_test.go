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

	core "github.com/assurrussa/goauth/core"
	rolesmiddleware "github.com/assurrussa/goauth/http/fiber/rolesmiddleware"
	oidcctx "github.com/assurrussa/goauth/http/oidcctx"
	integrationadminsession "github.com/assurrussa/goauth/integration/adminsession"
	integrationlocaljwt "github.com/assurrussa/goauth/integration/localjwt"
	integrationoidc "github.com/assurrussa/goauth/integration/oidc"
	integrationroles "github.com/assurrussa/goauth/integration/roles"
	integrationstorage "github.com/assurrussa/goauth/integration/storage"
	localpasswordauth "github.com/assurrussa/goauth/local/passwordauth"
	localpasswordreset "github.com/assurrussa/goauth/local/passwordreset"
	localtokenauth "github.com/assurrussa/goauth/local/tokenauth"
	migrations "github.com/assurrussa/goauth/migrations"
	oidc "github.com/assurrussa/goauth/oidc"
	oidcprovider "github.com/assurrussa/goauth/oidc/provider"
	oidcverifier "github.com/assurrussa/goauth/oidc/verifier"
	externalconsumer "github.com/assurrussa/goauth/reference/externalconsumer"
	authjwtservice "github.com/assurrussa/goauth/service/authjwtservice"
	adminaccount "github.com/assurrussa/goauth/session/adminaccount"
	sessionruntime "github.com/assurrussa/goauth/session/runtime"
	sso "github.com/assurrussa/goauth/sso"
	embeddedoidc "github.com/assurrussa/goauth/sso/embeddedoidc"
	externalidentity "github.com/assurrussa/goauth/sso/externalidentity"
	identitylink "github.com/assurrussa/goauth/sso/identitylink"
)

func TestPublicSurfaceCompiles(t *testing.T) {
	t.Helper()

	var _ core.Subject
	_ = core.StaticSubjectCredentials{}
	_ = core.Profile{}
	_ = core.SubjectProfilePatch{}
	var _ core.SubjectProfileWriter

	_ = rolesmiddleware.RequirePermission
	_ = rolesmiddleware.RequirePermissionGuard
	_ = localpasswordauth.Options{}
	_ = localtokenauth.Options{}
	_ = localpasswordreset.Options{}
	_ = adminaccount.Options{}
	_ = integrationlocaljwt.Options{}
	_ = integrationlocaljwt.Options{ProfileProvisioner: nil}
	_ = integrationlocaljwt.Kit{}
	var _ *integrationlocaljwt.UserAuthMeUseCase
	var _ *integrationlocaljwt.UserLoginUseCase
	var _ *integrationlocaljwt.UserLogoutUseCase
	var _ *integrationlocaljwt.UserLogoutAllUseCase
	var _ *integrationlocaljwt.UserRegisterUseCase
	var _ *integrationlocaljwt.UserTokenBanUseCase
	var _ *integrationlocaljwt.UserTokenRevokeUseCase
	var _ *integrationlocaljwt.UserTokenListUseCase
	var _ *integrationlocaljwt.UserTokenRefreshUseCase
	var _ *integrationlocaljwt.SendConfirmationCodeUseCase
	var _ *integrationlocaljwt.VerifyConfirmationCodeUseCase
	var _ *integrationlocaljwt.GetConfirmationInformationUseCase
	var _ *integrationlocaljwt.RequestPasswordResetUseCase
	var _ *integrationlocaljwt.PerformPasswordResetUseCase
	var _ *integrationlocaljwt.CleanerTokensUseCase
	var _ *integrationlocaljwt.CleanerPasswordResetsUseCase
	var _ *integrationlocaljwt.CleanerConfirmationCodesUseCase
	_ = integrationlocaljwt.UserAuthMeRequest{}
	_ = integrationlocaljwt.UserAuthMeResponse{}
	_ = integrationlocaljwt.UserLoginRequest{}
	_ = integrationlocaljwt.UserLoginResponse{}
	_ = integrationlocaljwt.UserLogoutRequest{}
	_ = integrationlocaljwt.UserLogoutResponse{}
	_ = integrationlocaljwt.UserLogoutAllRequest{}
	_ = integrationlocaljwt.UserLogoutAllResponse{}
	_ = integrationlocaljwt.UserRegisterRequest{}
	_ = integrationlocaljwt.UserRegisterResponse{}
	_ = integrationlocaljwt.UserTokenBanRequest{}
	_ = integrationlocaljwt.UserTokenBanResponse{}
	_ = integrationlocaljwt.UserTokenRevokeRequest{}
	_ = integrationlocaljwt.UserTokenRevokeResponse{}
	_ = integrationlocaljwt.UserTokenListRequest{}
	_ = integrationlocaljwt.UserTokenListItem{}
	_ = integrationlocaljwt.UserTokenListResponse{}
	_ = integrationlocaljwt.UserTokenRefreshRequest{}
	_ = integrationlocaljwt.UserTokenRefreshResponse{}
	_ = integrationlocaljwt.SendConfirmationCodeRequest{}
	_ = integrationlocaljwt.SendConfirmationCodeResponse{}
	_ = integrationlocaljwt.VerifyConfirmationCodeRequest{}
	_ = integrationlocaljwt.VerifyConfirmationCodeResponse{}
	_ = integrationlocaljwt.GetConfirmationInformationQuery{}
	_ = integrationlocaljwt.GetConfirmationInformationResult{}
	_ = integrationlocaljwt.RequestPasswordResetRequest{}
	_ = integrationlocaljwt.RequestPasswordResetResponse{}
	_ = integrationlocaljwt.PerformPasswordResetRequest{}
	_ = integrationlocaljwt.PerformPasswordResetResponse{}
	_ = integrationlocaljwt.CleanerTokensRequest{}
	_ = integrationlocaljwt.CleanerTokensResponse{}
	_ = integrationlocaljwt.CleanerPasswordResetsRequest{}
	_ = integrationlocaljwt.CleanerPasswordResetsResponse{}
	_ = integrationlocaljwt.CleanerConfirmationCodesRequest{}
	_ = integrationlocaljwt.CleanerConfirmationCodesResponse{}
	_ = integrationlocaljwt.NewUserAuthMeUseCase
	_ = integrationlocaljwt.NewUserLoginUseCase
	_ = integrationlocaljwt.NewUserLogoutUseCase
	_ = integrationlocaljwt.NewUserLogoutAllUseCase
	_ = integrationlocaljwt.NewUserRegisterUseCase
	_ = integrationlocaljwt.NewUserTokenBanUseCase
	_ = integrationlocaljwt.NewUserTokenRevokeUseCase
	_ = integrationlocaljwt.NewUserTokenListUseCase
	_ = integrationlocaljwt.NewUserTokenRefreshUseCase
	_ = integrationlocaljwt.NewSendConfirmationCodeUseCase
	_ = integrationlocaljwt.NewVerifyConfirmationCodeUseCase
	_ = integrationlocaljwt.NewRequestPasswordResetUseCase
	_ = integrationlocaljwt.NewPerformPasswordResetUseCase
	_ = integrationlocaljwt.NewCleanerTokensUseCase
	_ = integrationlocaljwt.MustCleanerTokensUseCase
	_ = integrationlocaljwt.NewCleanerPasswordResetsUseCase
	_ = integrationlocaljwt.MustCleanerPasswordResetsUseCase
	_ = integrationlocaljwt.NewCleanerConfirmationCodesUseCase
	_ = integrationlocaljwt.MustCleanerConfirmationCodesUseCase
	_ = integrationlocaljwt.ErrInvalidPasswordVersion
	_ = integrationlocaljwt.ErrInvalidLoginRequest
	_ = integrationlocaljwt.ErrInvalidLogoutRequest
	_ = integrationlocaljwt.ErrInvalidLogoutAllRequest
	_ = integrationlocaljwt.ErrInvalidRegisterRequest
	_ = integrationlocaljwt.ErrInvalidTokenRefreshRequest
	_ = integrationlocaljwt.ErrInvalidConfirmationRequest
	_ = integrationlocaljwt.ErrInvalidPasswordResetRequest
	_ = integrationlocaljwt.ErrInvalidPasswordResetToken
	_ = integrationlocaljwt.ErrInvalidPasswordResetConfirm
	_ = integrationadminsession.Options{}
	_ = integrationadminsession.Kit{}
	var _ *integrationadminsession.CleanerAdminEmailChangesUseCase
	_ = integrationadminsession.CleanerAdminEmailChangesRequest{}
	_ = integrationadminsession.CleanerAdminEmailChangesResponse{}
	_ = integrationadminsession.NewCleanerAdminEmailChangesUseCase
	_ = integrationadminsession.MustCleanerAdminEmailChangesUseCase
	_ = integrationoidc.Options{}
	_ = integrationoidc.Kit{}
	var _ *integrationoidc.RefreshTokenCleanerUseCase
	_ = integrationoidc.RefreshTokenCleanerRequest{}
	_ = integrationoidc.RefreshTokenCleanerResponse{}
	_ = integrationoidc.NewRefreshTokenCleanerUseCase
	_ = integrationoidc.MustRefreshTokenCleanerUseCase
	var _ *integrationroles.Repo
	var _ *integrationroles.Service
	var _ *integrationroles.Seed
	var _ integrationroles.SeedOption
	var _ integrationroles.RolePreset
	var _ *integrationroles.GuardCache
	var _ *integrationroles.GuardService
	_ = integrationroles.Role{}
	_ = integrationroles.Permission{}
	_ = integrationroles.PermissionWithRole{}
	_ = integrationroles.RolePermission{}
	_ = integrationroles.SubjectRole{}
	_ = integrationroles.RoleHierarchy{}
	var _ integrationroles.PermissionDomain
	var _ integrationroles.PermissionAction
	_ = integrationroles.PermissionKey{}
	_ = integrationroles.PermissionCatalog{}
	_ = integrationroles.PermissionDefinition{}
	var _ integrationroles.PermissionGuardOption
	_ = integrationroles.PermissionGuardConfig{}
	_ = integrationroles.RepoOptions{}
	var _ integrationroles.GuardCacheOption
	_ = integrationroles.GuardServiceOptions{}
	_ = integrationroles.RoleFilter{}
	_ = integrationroles.PermissionFilter{}
	var _ *integrationroles.ListRolesUseCase
	var _ *integrationroles.GetRoleUseCase
	var _ *integrationroles.CreateRoleUseCase
	var _ *integrationroles.UpdateRoleUseCase
	var _ *integrationroles.DeleteRoleUseCase
	var _ *integrationroles.SetRolePermissionsUseCase
	var _ *integrationroles.AssignSubjectRolesUseCase
	var _ *integrationroles.ListPermissionsUseCase
	var _ *integrationroles.ListRolePermissionsUseCase
	var _ *integrationroles.ListSubjectRolesUseCase
	var _ *integrationroles.ListAllRolesUseCase
	var _ *integrationstorage.ConfirmationCodeRepo
	var _ *integrationstorage.ConfirmationRepo
	var _ *integrationstorage.EmailChangeRepo
	var _ *integrationstorage.IdentityLinkRepo
	var _ *integrationstorage.OIDCRefreshTokenRepo
	var _ integrationstorage.OIDCRefreshTokenRepoOptions
	var _ integrationstorage.OIDCRefreshTokenRepoOptOptionsSetter
	var _ *integrationstorage.PasswordResetTokenRepo
	var _ *integrationstorage.RefreshTokenRepo
	var _ *integrationstorage.SessionRepo
	var _ *integrationstorage.SubjectRepo
	var _ integrationstorage.OIDCStateRedisClient
	var _ *integrationstorage.OIDCRequestStore
	var _ *integrationstorage.OIDCCodeStore
	_ = integrationroles.ListRolesRole{}
	_ = integrationroles.GetRolePermission{}
	_ = integrationroles.ListPermissionsPermission{}
	_ = integrationroles.ListRolePermissionsPermission{}
	_ = integrationroles.CreatePermissionInput{}
	_ = integrationroles.CreateRoleInput{}
	_ = integrationroles.UpdateRoleInput{}
	_ = integrationroles.ListRolesRequest{}
	_ = integrationroles.ListRolesResponse{}
	_ = integrationroles.GetRoleRequest{}
	_ = integrationroles.GetRoleResponse{}
	_ = integrationroles.CreateRoleRequest{}
	_ = integrationroles.CreateRoleResponse{}
	_ = integrationroles.UpdateRoleRequest{}
	_ = integrationroles.UpdateRoleResponse{}
	_ = integrationroles.DeleteRoleRequest{}
	_ = integrationroles.DeleteRoleResponse{}
	_ = integrationroles.SetRolePermissionsRequest{}
	_ = integrationroles.SetRolePermissionsResponse{}
	_ = integrationroles.AssignSubjectRolesRequest{}
	_ = integrationroles.AssignSubjectRolesResponse{}
	_ = integrationroles.ListPermissionsRequest{}
	_ = integrationroles.ListPermissionsResponse{}
	_ = integrationroles.ListRolePermissionsRequest{}
	_ = integrationroles.ListRolePermissionsResponse{}
	_ = integrationroles.ListSubjectRolesRequest{}
	_ = integrationroles.ListSubjectRolesResponse{}
	_ = integrationroles.ListAllRolesRequest{}
	_ = integrationroles.ListAllRolesResponse{}
	_ = integrationroles.NewRepo
	_ = integrationroles.MustRepo
	_ = integrationroles.NewService
	_ = integrationroles.MustService
	_ = integrationroles.NewSeed
	_ = integrationroles.WithPermissionDefinitions
	_ = integrationroles.WithRolePresets
	_ = integrationroles.WithGuardCacheSyncInterval
	_ = integrationroles.WithGuardCacheSyncCacheInterval
	_ = integrationroles.NewGuardServiceOptions
	_ = integrationroles.ErrInvalidRoleName
	_ = integrationroles.NewPermissionKey
	_ = integrationroles.ParsePermissionKey
	_ = integrationroles.DefaultPermissionDefinitions
	_ = integrationroles.NewPermissionCatalog
	_ = integrationroles.ClonePermissionDefinitions
	_ = integrationroles.MergePermissionDefinitions
	_ = integrationroles.CreateRoles
	_ = integrationroles.WithBypassRoles
	_ = integrationroles.ErrRoleNotFound
	_ = integrationroles.ErrPermissionNotFound
	_ = integrationroles.ErrAssignmentNotFound
	_ = integrationroles.ErrInvalidPermission
	_ = integrationroles.ErrInvalidRoleID
	_ = integrationroles.ErrInvalidRoleSlug
	_ = integrationroles.ErrInvalidSubjectID
	_ = integrationroles.ErrSystemRoleProtected
	_ = integrationroles.SuperAdminRole
	_ = integrationroles.SuperSubjectRole
	_ = integrationroles.PermissionDomainRoles
	_ = integrationroles.PermissionDomainPermissions
	_ = integrationroles.PermissionDomainAdmins
	_ = integrationroles.PermissionDomainDashboard
	_ = integrationroles.PermissionDomainOperations
	_ = integrationroles.PermissionDomainUsers
	_ = integrationroles.PermissionDomainUploads
	_ = integrationroles.PermissionDomainQueues
	_ = integrationroles.PermissionActionRead
	_ = integrationroles.PermissionActionCreate
	_ = integrationroles.PermissionActionUpdate
	_ = integrationroles.PermissionActionDelete
	_ = integrationroles.PermissionActionAssign
	_ = integrationroles.PermissionActionSync
	_ = integrationroles.NewGuardCache
	_ = integrationroles.NewGuardService
	_ = integrationroles.NewGuardServiceWithOptions
	_ = integrationroles.MustListRolesUseCase
	_ = integrationroles.MustGetRoleUseCase
	_ = integrationroles.MustCreateRoleUseCase
	_ = integrationroles.MustUpdateRoleUseCase
	_ = integrationroles.MustDeleteRoleUseCase
	_ = integrationroles.MustSetRolePermissionsUseCase
	_ = integrationroles.MustAssignSubjectRolesUseCase
	_ = integrationroles.MustListPermissionsUseCase
	_ = integrationroles.MustListRolePermissionsUseCase
	_ = integrationroles.MustListSubjectRolesUseCase
	_ = integrationroles.MustListAllRolesUseCase
	_ = integrationstorage.NewConfirmationCodeRepo
	_ = integrationstorage.MustConfirmationCodeRepo
	_ = integrationstorage.NewConfirmationRepo
	_ = integrationstorage.MustConfirmationRepo
	_ = integrationstorage.NewEmailChangeRepo
	_ = integrationstorage.MustEmailChangeRepo
	_ = integrationstorage.NewIdentityLinkRepo
	_ = integrationstorage.MustIdentityLinkRepo
	_ = integrationstorage.NewOIDCRefreshTokenRepoOptions
	_ = integrationstorage.NewOIDCRefreshTokenRepo
	_ = integrationstorage.MustOIDCRefreshTokenRepo
	_ = integrationstorage.NewPasswordResetTokenRepo
	_ = integrationstorage.MustPasswordResetTokenRepo
	_ = integrationstorage.NewRefreshTokenRepo
	_ = integrationstorage.MustRefreshTokenRepo
	_ = integrationstorage.NewSessionRepo
	_ = integrationstorage.MustSessionRepo
	_ = integrationstorage.NewSubjectRepo
	_ = integrationstorage.MustSubjectRepo
	_ = integrationstorage.NewOIDCRequestStore
	_ = integrationstorage.NewOIDCCodeStore
	_ = sessionruntime.Options[struct{}]{}
	_ = migrations.TableName
	_ = migrations.DatabaseConfig{}
	_ = authjwtservice.Options{ProfileProvisioner: nil}
	_ = authjwtservice.NewOptions
	_ = authjwtservice.New
	_ = authjwtservice.Must
	_ = authjwtservice.WithProfileProvisioner

	_ = oidc.Client{}
	_ = oidc.DefaultTokenEndpointAuthMethod
	_ = oidc.NormalizeTokenEndpointAuthMethod
	_ = oidc.ClientTokenEndpointAuthMethod
	_ = oidc.EncodeRSAPublicKeyJWK
	_ = oidc.DecodeRSAPublicKeyJWK
	_ = oidcprovider.NewDisabled
	_ = oidcverifier.Options{}
	_ = integrationoidc.New
	_ = integrationoidc.NewLinking
	var _ integrationoidc.AccessTokenVerifier
	var _ integrationoidc.ExternalIdentityResolver
	var _ integrationoidc.LinkedIdentityResolver

	_ = sso.ExternalIdentity{}
	_ = embeddedoidc.Disabled
	_ = identitylink.New
	_ = externalidentity.New
	_ = integrationlocaljwt.New
	_ = integrationadminsession.New
	_ = integrationadminsession.NewLegacySessionAdapter[struct{}]
	_ = integrationadminsession.MustLegacySessionAdapter[struct{}]
	var _ *integrationadminsession.LegacySessionAdapter[struct{}]
	_ = integrationoidc.NewBearerMiddleware
	_ = integrationoidc.NewLinkedSubjectMiddleware
	_ = integrationoidc.WriteBearerError

	_ = oidcctx.VerifiedAccessTokenCtxKey

	_ = migrations.Run
	_ = migrations.RunWithConfig
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

		if !strings.HasPrefix(path, "github.com/assurrussa/goauth/") {
			continue
		}
		if path == "github.com/assurrussa/goauth/reference/externalconsumer" {
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

func TestReleaseDocsDoNotAdvertiseHostSupportPackages(t *testing.T) {
	t.Helper()

	bannedByFile := map[string][]string{
		"README.md": {
			"packages that are release-visible because `backend`",
			"The host-support surface currently covers",
			"storage/pgsql/*",
			"storage/redis/oidcstate",
			"domain/roles/repository/postgres",
			"domain/roles/service/roles",
			"domain/roles/usecases/*",
		},
		"RELEASING.md": {
			"and host-support packages",
			"Review `HostSupportPackages` before tagging",
			"keep concrete storage adapters",
			"legacy Fiber",
			"cache/seed helpers",
		},
	}

	var offenders []string
	for filename, bannedSnippets := range bannedByFile {
		content, err := os.ReadFile(filename)
		if err != nil {
			t.Fatalf("read %s: %v", filename, err)
		}

		source := string(content)
		for _, bannedSnippet := range bannedSnippets {
			if strings.Contains(source, bannedSnippet) {
				offenders = append(offenders, filename+" -> "+bannedSnippet)
			}
		}
	}

	slices.Sort(offenders)
	if len(offenders) != 0 {
		t.Fatalf("release docs still advertise host-support or direct implementation packages:\n%s", strings.Join(offenders, "\n"))
	}
}

func TestReleaseDocsDocumentConsumerSwitchState(t *testing.T) {
	t.Helper()

	content, err := os.ReadFile("RELEASING.md")
	if err != nil {
		t.Fatalf("read RELEASING.md: %v", err)
	}

	requiredSnippets := []string{
		"## Current consumer state",
		"`backend/go.mod` requires `github.com/assurrussa/goauth v0.1.5`",
		"`backend/go.mod` has no local `replace` for `github.com/assurrussa/goauth`",
		"`goadmin/go.mod` requires `github.com/assurrussa/goauth v0.1.5`",
		"`goadmin/go.mod` has no local `replace` for `github.com/assurrussa/goauth`",
		"`go list -m -json github.com/assurrussa/goauth@v0.1.5`",
		"`go get github.com/assurrussa/goauth@v0.1.5`",
		"use `GOAUTH_LOCAL_PATH` only for explicit sibling-development checks",
	}

	var missing []string
	for _, snippet := range requiredSnippets {
		if !strings.Contains(string(content), snippet) {
			missing = append(missing, snippet)
		}
	}

	slices.Sort(missing)
	if len(missing) != 0 {
		t.Fatalf("release docs do not describe current consumer switch state:\n%s", strings.Join(missing, "\n"))
	}
}

func TestReleaseDocsDocumentLoginProjectionProvisioning(t *testing.T) {
	t.Helper()

	content, err := os.ReadFile("RELEASING.md")
	if err != nil {
		t.Fatalf("read RELEASING.md: %v", err)
	}

	requiredSnippets := []string{
		"`authjwtservice.WithProfileProvisioner`",
		"`localjwt.Options.ProfileProvisioner`",
		"`authcore.ProfileProvisioner`",
		"canonical subjects can create or restore host projections during successful Local JWT login",
	}

	var missing []string
	for _, snippet := range requiredSnippets {
		if !strings.Contains(string(content), snippet) {
			missing = append(missing, snippet)
		}
	}

	slices.Sort(missing)
	if len(missing) != 0 {
		t.Fatalf("release docs do not describe login projection provisioning:\n%s", strings.Join(missing, "\n"))
	}
}
