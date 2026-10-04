package externalconsumerprobe

const sessionOIDCProbeTest = `
var _ func(*postgres.SessionOIDCState, context.Context) (postgres.SessionOIDCCleanupResult, error) =
 (*postgres.SessionOIDCState).CleanupExpired
var _ oidc.SessionStateStore =
 (*postgres.SessionOIDCState)(nil)
var _ func(provider.SessionOptions) (*provider.SessionService, error) = provider.NewSessionBound
var _ func(
 *provider.SessionService, context.Context, oidc.SessionAuthorizeRequest, *oidc.BrowserSession,
) (*oidc.AuthorizeResult, error) =
 (*provider.SessionService).Authorize
var _ func(*provider.SessionService, context.Context, string, *oidc.BrowserSession, string) (*oidc.AuthorizeResult, error) =
 (*provider.SessionService).ContinueAuthorization
var _ func(*provider.SessionService, context.Context, oidc.TokenRequest) (*oidc.TokenResponse, error) =
 (*provider.SessionService).ExchangeToken
var _ func(*provider.SessionService, context.Context, string) (oidc.SessionUserInfo, error) =
 (*provider.SessionService).UserInfo
var _ func(*provider.SessionService, context.Context, oidc.RevokeRequest) error =
 (*provider.SessionService).Revoke
var _ func(*postgres.SessionOIDCState, context.Context, string, string, oidc.RequestLoginCompletion) error =
 (*postgres.SessionOIDCState).MarkLoginComplete

func TestSessionBoundProfileExternalSurface(t *testing.T) {
 if _, err := postgres.NewSessionOIDCState(nil); err == nil { t.Fatal("nil runtime accepted") }
 if _, err := provider.NewSessionBound(provider.SessionOptions{}); err == nil { t.Fatal("incomplete strict assembly accepted") }
 _ = oidc.SessionBinding{
 SubjectID:"subject",SecurityVersion:1,ClientID:"client",SessionID:"sid",PolicyStamp:"opaque",
 AuthenticatedAt:time.Now(),AbsoluteExpiresAt:time.Now().Add(time.Hour)}
 _ = oidc.SessionProjection{
 ProjectID:"project",Profile:map[string]string{"name":"display"},Project:map[string]string{"team":"blue"}}
 _ = oidc.SessionAdmissionRequest{Expected:nil,ClientRevision:1}
 _ = oidc.SessionAdmissionResult{Allowed:false}
 _ = oidc.SessionRequest{ClientRevision:1,LoginCompletion:&oidc.RequestLoginCompletion{CookieDigest:"digest"}}
 _ = oidc.SessionCode{Binding:oidc.SessionBinding{},FamilyID:"family"}
 _ = oidc.SessionRefresh{Binding:oidc.SessionBinding{},FamilyID:"family"}
 _ = oidc.SessionFamily{Scopes:[]string{"openid"}}
 _ = oidc.SessionRevoked
 _ = oidc.SessionReplay
 if !errors.Is(oidc.ErrSessionStateConflict,oidc.ErrSessionStateConflict) { t.Fatal("state sentinel unavailable") }
}
`
