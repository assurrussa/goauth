package goauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	MaxAccessTokenTTL              = 5 * time.Minute
	defaultSessionTTL              = 30 * 24 * time.Hour
	defaultRefreshTTL              = 30 * 24 * time.Hour
	defaultPasswordResetTTL        = 15 * time.Minute
	defaultChallengeTTL            = 10 * time.Minute
	defaultEmailChangeTTL          = 10 * time.Minute
	defaultEnvelopeRetention       = 24 * time.Hour
	defaultResetResponseFloor      = 50 * time.Millisecond
	defaultLinkAuthMaxAge          = 10 * time.Minute
	defaultLoginRateWindow         = 15 * time.Minute
	defaultPasswordResetRateWindow = time.Hour
)

type Config struct {
	Store                   RuntimeStore
	Signing                 SigningConfig
	TokenHMACKeys           KeyRing
	OutboxAEADKeys          KeyRing
	EventSink               EncryptedEventSink
	NotificationTransaction NotificationTransaction // Deprecated: use AuthTransaction.
	AuthTransaction         AuthTransaction
	// Nil allows all trusted issuers; empty disables verified-email auto-linking.
	AutoLinkVerifiedEmailIssuers []string
	// ManagedNotificationDelivery enables typed, lease-owned PostgreSQL delivery.
	// A custom transaction alone keeps the configured renderer and event sink.
	ManagedNotificationDelivery bool
	IdentifierResolvers         map[IdentifierScheme]IdentifierResolver
	MembershipGate              MembershipGate
	ClaimsEnricher              ClaimsEnricher
	NotificationRenderer        NotificationRenderer
	URLBuilder                  URLBuilder
	AuditSink                   AuditSink
	PasswordHasher              PasswordHasher
	// Zero defaults to four concurrent hashes/verifications per shared Runtime.
	// Excess work fails immediately with ErrPasswordHashOverloaded.
	MaxConcurrentPasswordHashes int
	PasswordPolicy              PasswordPolicy
	AdditionalRealms            []Realm
	AccessTTL                   time.Duration
	SessionTTL                  time.Duration
	RefreshTTL                  time.Duration
	PasswordResetTTL            time.Duration
	ChallengeTTL                time.Duration
	EmailChangeTTL              time.Duration
	EnvelopeRetention           time.Duration
	ResetResponseFloor          time.Duration
	IdentityLinkAuthMaxAge      time.Duration
	LoginRateLimit              RateLimitPolicy
	PasswordResetRateLimit      RateLimitPolicy
	Now                         func() time.Time
	Random                      io.Reader
}

type Runtime struct {
	store                       RuntimeStore
	identifiers                 map[IdentifierScheme]IdentifierResolver
	membership                  MembershipGate
	claims                      ClaimsEnricher
	renderer                    NotificationRenderer
	urlBuilder                  URLBuilder
	eventSink                   EncryptedEventSink
	authTransaction             AuthTransaction
	autoLinkIssuers             []string
	managedNotificationDelivery bool
	audit                       AuditSink
	hasher                      PasswordHasher
	passwordPolicy              PasswordPolicy
	realms                      map[Realm]struct{}
	secretCodec                 *secretCodec
	envelopes                   *envelopeCipher
	jwt                         *jwtIssuer
	dummyPasswordPHC            string
	accessTTL                   time.Duration
	sessionTTL                  time.Duration
	refreshTTL                  time.Duration
	passwordResetTTL            time.Duration
	challengeTTL                time.Duration
	emailChangeTTL              time.Duration
	envelopeRetention           time.Duration
	resetResponseFloor          time.Duration
	identityLinkAuthMaxAge      time.Duration
	loginRateLimit              RateLimitPolicy
	passwordResetRateLimit      RateLimitPolicy
	now                         func() time.Time
	random                      io.Reader
}

func NewRuntime(config Config) (*Runtime, error) {
	if config.ManagedNotificationDelivery && config.NotificationRenderer != nil {
		return nil, errors.New("managed notification delivery does not support a custom renderer")
	}
	config = applyRuntimeDefaults(config)
	if err := validateRuntimeConfig(config); err != nil {
		return nil, err
	}

	jwt, err := newJWTIssuer(config.Signing, config.Now)
	if err != nil {
		return nil, err
	}
	if config.PasswordHasher == nil {
		config.PasswordHasher, err = NewArgon2idHasher(Argon2idConfig{Random: config.Random})
		if err != nil {
			return nil, err
		}
	}
	if config.PasswordPolicy.MinLength == 0 &&
		config.PasswordPolicy.MaxLength == 0 &&
		config.PasswordPolicy.Blocklist == nil && !config.PasswordPolicy.DisableBlocklist {
		config.PasswordPolicy = DefaultPasswordPolicy()
	}
	config.PasswordHasher = &boundedPasswordHasher{
		delegate: config.PasswordHasher,
		active:   make(chan struct{}, config.MaxConcurrentPasswordHashes),
	}
	dummyPHC, err := config.PasswordHasher.HashPassword("goauth-enumeration-dummy-password")
	if err != nil {
		return nil, fmt.Errorf("create enumeration-safe password hash: %w", err)
	}
	identifierResolvers, err := runtimeIdentifierResolvers(config.IdentifierResolvers)
	if err != nil {
		return nil, err
	}
	realms, err := runtimeRealms(config.AdditionalRealms)
	if err != nil {
		return nil, err
	}

	return &Runtime{
		store:                       config.Store,
		identifiers:                 identifierResolvers,
		membership:                  config.MembershipGate,
		claims:                      config.ClaimsEnricher,
		renderer:                    config.NotificationRenderer,
		urlBuilder:                  config.URLBuilder,
		eventSink:                   config.EventSink,
		authTransaction:             config.AuthTransaction,
		autoLinkIssuers:             append([]string(nil), config.AutoLinkVerifiedEmailIssuers...),
		managedNotificationDelivery: config.ManagedNotificationDelivery,
		audit:                       config.AuditSink,
		hasher:                      config.PasswordHasher,
		passwordPolicy:              config.PasswordPolicy,
		realms:                      realms,
		secretCodec:                 newSecretCodec(config.TokenHMACKeys, config.Random),
		envelopes:                   newEnvelopeCipher(config.OutboxAEADKeys, config.Random, config.Now),
		jwt:                         jwt,
		dummyPasswordPHC:            dummyPHC,
		accessTTL:                   config.AccessTTL,
		sessionTTL:                  config.SessionTTL,
		refreshTTL:                  config.RefreshTTL,
		passwordResetTTL:            config.PasswordResetTTL,
		challengeTTL:                config.ChallengeTTL,
		emailChangeTTL:              config.EmailChangeTTL,
		envelopeRetention:           config.EnvelopeRetention,
		resetResponseFloor:          config.ResetResponseFloor,
		identityLinkAuthMaxAge:      config.IdentityLinkAuthMaxAge,
		loginRateLimit:              config.LoginRateLimit,
		passwordResetRateLimit:      config.PasswordResetRateLimit,
		now:                         config.Now,
		random:                      config.Random,
	}, nil
}

func applyRuntimeDefaults(config Config) Config {
	if config.MaxConcurrentPasswordHashes == 0 {
		config.MaxConcurrentPasswordHashes = DefaultMaxConcurrentPasswordHashes
	}
	if config.AutoLinkVerifiedEmailIssuers == nil {
		config.AutoLinkVerifiedEmailIssuers = []string{"*"}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.AccessTTL == 0 {
		config.AccessTTL = MaxAccessTokenTTL
	}
	if config.SessionTTL == 0 {
		config.SessionTTL = defaultSessionTTL
	}
	if config.RefreshTTL == 0 {
		config.RefreshTTL = defaultRefreshTTL
	}
	if config.PasswordResetTTL == 0 {
		config.PasswordResetTTL = defaultPasswordResetTTL
	}
	if config.ChallengeTTL == 0 {
		config.ChallengeTTL = defaultChallengeTTL
	}
	if config.EmailChangeTTL == 0 {
		config.EmailChangeTTL = defaultEmailChangeTTL
	}
	if config.EnvelopeRetention == 0 {
		config.EnvelopeRetention = defaultEnvelopeRetention
	}
	if config.ResetResponseFloor == 0 {
		config.ResetResponseFloor = defaultResetResponseFloor
	}
	if config.IdentityLinkAuthMaxAge == 0 {
		config.IdentityLinkAuthMaxAge = defaultLinkAuthMaxAge
	}
	if config.LoginRateLimit == (RateLimitPolicy{}) {
		config.LoginRateLimit = RateLimitPolicy{Window: defaultLoginRateWindow, Limit: 10}
	}
	if config.PasswordResetRateLimit == (RateLimitPolicy{}) {
		config.PasswordResetRateLimit = RateLimitPolicy{Window: defaultPasswordResetRateWindow, Limit: 5}
	}
	if config.NotificationRenderer == nil {
		config.NotificationRenderer = jsonNotificationRenderer{}
	}

	return config
}

func validateRuntimeConfig(config Config) error {
	if config.MaxConcurrentPasswordHashes < 1 || config.MaxConcurrentPasswordHashes > 64 {
		return errors.New("password hash concurrency must be between one and 64")
	}
	if config.AuthTransaction == nil {
		return errors.New("auth transaction is required")
	}
	for _, issuer := range config.AutoLinkVerifiedEmailIssuers {
		if issuer == "" || (issuer == "*" && len(config.AutoLinkVerifiedEmailIssuers) != 1) {
			return errors.New("invalid auto-link issuer policy")
		}
	}
	if config.AuditSink == nil {
		return errors.New("transactional audit sink is required")
	}
	if config.NotificationTransaction != nil {
		return errors.New("NotificationTransaction is retired; configure AuthTransaction")
	}
	if config.Store == nil {
		return errors.New("runtime store is required")
	}
	if config.EventSink == nil {
		return ErrNotificationSinkRequired
	}
	if config.URLBuilder == nil {
		return ErrURLBuilderRequired
	}
	if config.AccessTTL < time.Second || config.AccessTTL > MaxAccessTokenTTL {
		return fmt.Errorf("access token TTL must be between one second and %s", MaxAccessTokenTTL)
	}
	if config.ResetResponseFloor < 0 {
		return errors.New("reset response floor cannot be negative")
	}
	if config.IdentityLinkAuthMaxAge < time.Minute || config.IdentityLinkAuthMaxAge > time.Hour {
		return errors.New("identity linking authentication age must be between one minute and one hour")
	}
	if err := config.LoginRateLimit.Validate(); err != nil {
		return fmt.Errorf("login rate limit: %w", err)
	}
	if err := config.PasswordResetRateLimit.Validate(); err != nil {
		return fmt.Errorf("password reset rate limit: %w", err)
	}
	if config.SessionTTL <= 0 || config.RefreshTTL <= 0 || config.PasswordResetTTL <= 0 ||
		config.ChallengeTTL <= 0 || config.EmailChangeTTL <= 0 || config.EnvelopeRetention <= 0 {
		return errors.New("runtime security TTLs must be positive")
	}
	return validateDistinctKeyRings(config.Signing.Keys, config.TokenHMACKeys, config.OutboxAEADKeys)
}

func runtimeIdentifierResolvers(
	configured map[IdentifierScheme]IdentifierResolver,
) (map[IdentifierScheme]IdentifierResolver, error) {
	identifierResolvers := make(map[IdentifierScheme]IdentifierResolver, len(configured)+1)
	identifierResolvers[IdentifierSchemeEmail] = emailIdentifierResolver{}
	for scheme, resolver := range configured {
		if scheme == IdentifierSchemeEmail || resolver == nil {
			continue
		}
		if err := scheme.Validate(); err != nil {
			return nil, err
		}
		identifierResolvers[scheme] = resolver
	}

	return identifierResolvers, nil
}

func runtimeRealms(additional []Realm) (map[Realm]struct{}, error) {
	realms := map[Realm]struct{}{RealmUser: {}, RealmAdmin: {}}
	for _, realm := range additional {
		if err := realm.Validate(); err != nil {
			return nil, err
		}
		realms[realm] = struct{}{}
	}

	return realms, nil
}

type RegisterRequest struct {
	Email    string
	Password string
	Profile  BasicProfile
}

type RegisterResult struct {
	Account Account
	Tokens  TokenPair
}

func (r *Runtime) Register(ctx context.Context, request RegisterRequest) (RegisterResult, error) {
	record, err := r.prepareLocalAccount(ctx, request, false)
	if err != nil {
		return RegisterResult{}, err
	}
	prepared, err := r.prepareSession(ctx, record.Account, RealmUser, SessionScopeConfirmation)
	if err != nil {
		return RegisterResult{}, err
	}
	err = r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		if _, err := r.store.CreateLocalAccount(ctx, record); err != nil {
			return err
		}
		return r.store.CreateSession(ctx, prepared.record)
	})
	if err != nil {
		return RegisterResult{}, err
	}
	return RegisterResult{Account: record.Account, Tokens: prepared.tokens}, nil
}

type LoginRequest struct {
	Credential Credential
	Realm      Realm
}

type LoginResult struct {
	Account Account
	Tokens  TokenPair
}

func (r *Runtime) Login(ctx context.Context, request LoginRequest) (LoginResult, error) {
	realm := request.Realm
	if realm == "" {
		realm = RealmUser
	}
	if err := r.validateRealm(realm); err != nil {
		return LoginResult{}, err
	}
	identifier, err := r.normalizeIdentifier(ctx, request.Credential.Identifier)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	allowed, err := r.takeIdentifierRateLimit(ctx, "login", identifier, r.loginRateLimit)
	if err != nil {
		return LoginResult{}, fmt.Errorf("check login rate limit: %w", err)
	}
	if !allowed {
		return LoginResult{}, ErrAuthenticationRateLimited
	}
	record, lookupErr := r.store.FindLocalAccount(ctx, identifier)
	passwordPHC := record.PasswordPHC
	if lookupErr != nil || record.Account.IsZero() || passwordPHC == "" {
		passwordPHC = r.dummyPasswordPHC
	}
	passwordErr := r.hasher.VerifyPassword(passwordPHC, request.Credential.Password)
	if lookupErr != nil && !errors.Is(lookupErr, ErrAccountNotFound) {
		return LoginResult{}, fmt.Errorf("find local credential: %w", lookupErr)
	}
	if passwordErr != nil && !errors.Is(passwordErr, ErrInvalidCredentials) {
		return LoginResult{}, fmt.Errorf("verify password: %w", passwordErr)
	}
	if lookupErr != nil || passwordErr != nil || record.Account.IsZero() {
		_ = r.recordAudit(ctx, SecurityEvent{Type: SecurityEventLoginFailed, Realm: realm, At: r.now().UTC()})
		return LoginResult{}, ErrInvalidCredentials
	}
	if record.Account.Subject.Status != SubjectStatusActive {
		return LoginResult{}, ErrAccountUnavailable
	}
	scope, err := r.authorizeRealm(ctx, realm, record.Account)
	if err != nil {
		return LoginResult{}, err
	}
	tokens, err := r.issueSession(ctx, record.Account, realm, scope)
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{Account: record.Account, Tokens: tokens}, nil
}

func (r *Runtime) Refresh(ctx context.Context, rawRefreshToken string) (TokenPair, error) {
	current, digest, err := r.secretCodec.Parse(strings.TrimSpace(rawRefreshToken), "refresh")
	if err != nil {
		return TokenPair{}, ErrInvalidToken
	}
	request := RefreshRotationRequest{CurrentSelector: current.selector, CurrentDigest: digest, Now: r.now().UTC()}
	snapshot, err := r.store.PeekRefresh(ctx, request)
	if err != nil {
		return TokenPair{}, fmt.Errorf("inspect refresh token: %w", err)
	}
	var tokens TokenPair
	if snapshot.Status == RefreshRotationSucceeded {
		if _, err := r.authorizeRealm(ctx, snapshot.Session.Realm, snapshot.Account); err != nil {
			return TokenPair{}, err
		}
		next, nextDigest, err := r.secretCodec.Generate("refresh")
		if err != nil {
			return TokenPair{}, err
		}
		request.NextSelector = next.selector
		request.NextDigest = nextDigest
		request.NextExpiresAt = capExpiry(request.Now.Add(r.refreshTTL), snapshot.Session.ExpiresAt)
		request.ExpectedSecurityVersion = snapshot.Account.Subject.SecurityVersion
		request.ExpectedNormalizedEmail = snapshot.Account.PrimaryEmail.NormalizedValue
		request.ExpectedEmailVerified = snapshot.Account.EmailVerified()
		expiry := capExpiry(request.Now.Add(r.accessTTL), snapshot.Session.ExpiresAt)
		access, err := r.jwt.Sign(ctx, snapshot.Account, snapshot.Session, expiry, r.claims)
		if err != nil {
			return TokenPair{}, err
		}
		tokens = TokenPair{
			AccessToken: access, RefreshToken: next.raw, AccessExpiresAt: expiry,
			RefreshExpiresAt: request.NextExpiresAt, Session: snapshot.Session,
		}
	} else if snapshot.Status != RefreshRotationReplayed {
		return TokenPair{}, refreshOutcome(snapshot.Status)
	}
	var result RefreshRotationResult
	err = r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		var err error
		request.Now = r.now().UTC()
		result, err = r.store.RotateRefresh(ctx, request)
		if err != nil {
			return err
		}
		if result.Status == RefreshRotationReplayed {
			return r.recordAudit(ctx, SecurityEvent{
				Type: SecurityEventRefreshReplay, SubjectID: result.Account.Subject.ID,
				Realm: result.Session.Realm, At: request.Now,
			})
		}
		return nil
	})
	if err != nil {
		return TokenPair{}, fmt.Errorf("rotate refresh token: %w", err)
	}
	if err := refreshOutcome(result.Status); err != nil {
		return TokenPair{}, err
	}
	return tokens, nil
}

func refreshOutcome(status RefreshRotationStatus) error {
	switch status {
	case RefreshRotationSucceeded:
		return nil
	case RefreshRotationReplayed:
		return ErrRefreshReplay
	case RefreshRotationExpired:
		return ErrExpiredToken
	case RefreshRotationRevoked:
		return ErrSessionRevoked
	default:
		return ErrInvalidToken
	}
}

// VerifyJWT validates an access JWT offline. Revocation takes effect only when
// it expires; use AuthenticateSession for current authorization.
func (r *Runtime) VerifyJWT(ctx context.Context, token string) (AuthContext, error) {
	return r.verifyAccessToken(ctx, token, false)
}

// AuthenticateSession validates current session/security state and realm membership.
func (r *Runtime) AuthenticateSession(ctx context.Context, token string) (AuthContext, error) {
	return r.verifyAccessToken(ctx, token, true)
}

// VerifyAccessToken is retained for source compatibility.
//
// Deprecated: use VerifyJWT or AuthenticateSession explicitly.
func (r *Runtime) VerifyAccessToken(ctx context.Context, token string, introspect bool) (AuthContext, error) {
	return r.verifyAccessToken(ctx, token, introspect)
}

func (r *Runtime) verifyAccessToken(ctx context.Context, rawAccessToken string, introspect bool) (AuthContext, error) {
	auth, err := r.jwt.Verify(strings.TrimSpace(rawAccessToken))
	if err != nil {
		return AuthContext{}, err
	}
	if err := r.validateRealm(auth.Realm); err != nil {
		return AuthContext{}, ErrInvalidToken
	}
	if !introspect {
		return auth, nil
	}
	security, err := r.store.IntrospectSession(ctx, auth.SessionID)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrAccountNotFound) {
			return AuthContext{}, ErrInvalidToken
		}
		return AuthContext{}, fmt.Errorf("introspect session: %w", err)
	}
	now := r.now().UTC()
	if !security.Session.Active(now) {
		return AuthContext{}, ErrSessionRevoked
	}
	if security.SubjectStatus != SubjectStatusActive {
		return AuthContext{}, ErrAccountUnavailable
	}
	if security.CurrentVersion != auth.SecurityVersion || security.Session.SecurityVersion != auth.SecurityVersion {
		return AuthContext{}, ErrSecurityVersionMismatch
	}
	if security.Session.SubjectID != auth.SubjectID || security.Session.Realm != auth.Realm || security.Session.Scope != auth.Scope {
		return AuthContext{}, ErrInvalidToken
	}

	if auth.Realm != RealmUser {
		account, err := r.store.GetAccount(ctx, auth.SubjectID)
		if err != nil {
			return AuthContext{}, err
		}
		if _, err := r.authorizeRealm(ctx, auth.Realm, account); err != nil {
			return AuthContext{}, err
		}
	}
	return auth, nil
}

func (r *Runtime) SetSubjectStatus(ctx context.Context, subjectID SubjectID, status SubjectStatus) (Subject, error) {
	if subjectID.IsZero() {
		return Subject{}, ErrAccountNotFound
	}
	if err := status.Validate(); err != nil {
		return Subject{}, err
	}
	var subject Subject
	err := r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		var err error
		subject, err = r.store.SetSubjectStatus(ctx, subjectID, status, r.now().UTC())
		if err != nil {
			return fmt.Errorf("set subject status: %w", err)
		}
		return r.recordAudit(ctx, SecurityEvent{
			Type:       SecurityEventSubjectStatusChanged,
			SubjectID:  subjectID,
			At:         r.now().UTC(),
			Attributes: map[string]string{"status": string(status)},
		})
	})
	if err != nil {
		return Subject{}, err
	}

	return subject, nil
}

type preparedSession struct {
	record SessionRecord
	tokens TokenPair
}

func (r *Runtime) issueSession(ctx context.Context, account Account, realm Realm, scope SessionScope) (TokenPair, error) {
	prepared, err := r.prepareSession(ctx, account, realm, scope)
	if err != nil {
		return TokenPair{}, err
	}
	err = r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		return r.store.CreateSession(ctx, prepared.record)
	})
	if err != nil {
		return TokenPair{}, err
	}
	return prepared.tokens, nil
}

func (r *Runtime) prepareSession(ctx context.Context, account Account, realm Realm, scope SessionScope) (preparedSession, error) {
	now := r.now().UTC()
	refresh, digest, err := r.secretCodec.Generate("refresh")
	if err != nil {
		return preparedSession{}, err
	}
	refreshExpiresAt := now.Add(r.refreshTTL)
	sessionExpiresAt := now.Add(r.sessionTTL)
	if refreshExpiresAt.Before(sessionExpiresAt) {
		sessionExpiresAt = refreshExpiresAt
	}
	refreshExpiresAt = sessionExpiresAt
	session := Session{
		ID:              uuid.NewString(),
		SubjectID:       account.Subject.ID,
		Realm:           realm,
		Scope:           scope,
		SecurityVersion: account.Subject.SecurityVersion,
		CreatedAt:       now,
		ExpiresAt:       sessionExpiresAt,
	}
	record := SessionRecord{
		Session:          session,
		FamilyID:         uuid.NewString(),
		RefreshSelector:  refresh.selector,
		RefreshDigest:    digest,
		RefreshExpiresAt: refreshExpiresAt,
	}
	accessExpiresAt := capExpiry(now.Add(r.accessTTL), sessionExpiresAt)
	accessToken, err := r.jwt.Sign(ctx, account, session, accessExpiresAt, r.claims)
	if err != nil {
		return preparedSession{}, err
	}

	return preparedSession{record: record, tokens: TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     refresh.raw,
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
		Session:          session,
	}}, nil
}

func capExpiry(expiry, absolute time.Time) time.Time {
	if absolute.Before(expiry) {
		return absolute
	}
	return expiry
}

func (r *Runtime) authorizeRealm(ctx context.Context, realm Realm, account Account) (SessionScope, error) {
	if realm == RealmUser && !account.EmailVerified() {
		return SessionScopeConfirmation, nil
	}
	if !account.EmailVerified() {
		return "", ErrEmailVerificationRequired
	}
	if realm != RealmUser {
		if r.membership == nil {
			return "", ErrMembershipDenied
		}
		if err := r.membership.AllowMembership(ctx, realm, account); err != nil {
			return "", errors.Join(ErrMembershipDenied, err)
		}
	}

	return SessionScopeAuthenticated, nil
}

func (r *Runtime) normalizeIdentifier(ctx context.Context, input IdentifierInput) (IdentifierInput, error) {
	if input.Scheme == "" {
		input.Scheme = IdentifierSchemeEmail
	}
	resolver, ok := r.identifiers[input.Scheme]
	if !ok {
		return IdentifierInput{}, fmt.Errorf("%w: %s", ErrInvalidIdentifierScheme, input.Scheme)
	}
	normalized, err := resolver.NormalizeIdentifier(ctx, input)
	if err != nil {
		return IdentifierInput{}, err
	}
	if normalized.Scheme != input.Scheme || strings.TrimSpace(normalized.Value) == "" {
		return IdentifierInput{}, ErrInvalidIdentifier
	}

	return normalized, nil
}

func (r *Runtime) validateRealm(realm Realm) error {
	if err := realm.Validate(); err != nil {
		return err
	}
	if _, ok := r.realms[realm]; !ok {
		return fmt.Errorf("%w: %s", ErrRealmNotRegistered, realm)
	}

	return nil
}

func (r *Runtime) recordAudit(ctx context.Context, event SecurityEvent) error {
	event.Attributes = cloneStringMap(event.Attributes)
	if event.At.IsZero() {
		event.At = r.now().UTC()
	}
	if err := r.audit.RecordSecurityEvent(ctx, event); err != nil {
		return fmt.Errorf("record security audit event: %w", err)
	}

	return nil
}
