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
	NotificationTransaction NotificationTransaction
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
	notificationTransaction     NotificationTransaction
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
		config.PasswordPolicy.Blocklist == nil {
		config.PasswordPolicy = DefaultPasswordPolicy()
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
		notificationTransaction:     config.NotificationTransaction,
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
	if config.AuditSink == nil {
		config.AuditSink = AuditSinkFunc(func(context.Context, SecurityEvent) error { return nil })
	}

	return config
}

func validateRuntimeConfig(config Config) error {
	if config.ManagedNotificationDelivery && config.NotificationTransaction == nil {
		return errors.New("managed notification delivery requires a notification transaction")
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
	account, err := r.createLocalAccount(ctx, request, false)
	if err != nil {
		return RegisterResult{}, err
	}
	tokens, err := r.issueSession(ctx, account, RealmUser, SessionScopeConfirmation)
	if err != nil {
		return RegisterResult{}, err
	}

	return RegisterResult{Account: account, Tokens: tokens}, nil
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
	current, currentDigest, err := r.secretCodec.Parse(strings.TrimSpace(rawRefreshToken), "refresh")
	if err != nil {
		return TokenPair{}, ErrInvalidToken
	}
	next, nextDigest, err := r.secretCodec.Generate("refresh")
	if err != nil {
		return TokenPair{}, err
	}
	now := r.now().UTC()
	result, err := r.store.RotateRefresh(ctx, RefreshRotationRequest{
		CurrentSelector: current.selector,
		CurrentDigest:   currentDigest,
		NextSelector:    next.selector,
		NextDigest:      nextDigest,
		NextExpiresAt:   now.Add(r.refreshTTL),
		Now:             now,
	})
	if err != nil {
		return TokenPair{}, fmt.Errorf("rotate refresh token: %w", err)
	}
	switch result.Status {
	case RefreshRotationReplayed:
		_ = r.recordAudit(ctx, SecurityEvent{
			Type:      SecurityEventRefreshReplay,
			SubjectID: result.Account.Subject.ID,
			Realm:     result.Session.Realm,
			At:        now,
		})
		return TokenPair{}, ErrRefreshReplay
	case RefreshRotationExpired:
		return TokenPair{}, ErrExpiredToken
	case RefreshRotationRevoked:
		return TokenPair{}, ErrSessionRevoked
	case RefreshRotationInvalid:
		return TokenPair{}, ErrInvalidToken
	case RefreshRotationSucceeded:
	default:
		return TokenPair{}, ErrInvalidToken
	}
	if result.Account.Subject.Status != SubjectStatusActive {
		return TokenPair{}, ErrAccountUnavailable
	}
	if _, err := r.authorizeRealm(ctx, result.Session.Realm, result.Account); err != nil {
		return TokenPair{}, err
	}
	accessExpiresAt := now.Add(r.accessTTL)
	accessToken, err := r.jwt.Sign(ctx, result.Account, result.Session, accessExpiresAt, r.claims)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     next.raw,
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: now.Add(r.refreshTTL),
		Session:          result.Session,
	}, nil
}

func (r *Runtime) VerifyAccessToken(ctx context.Context, rawAccessToken string, introspect bool) (AuthContext, error) {
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
		return AuthContext{}, ErrInvalidToken
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

	return auth, nil
}

func (r *Runtime) SetSubjectStatus(ctx context.Context, subjectID SubjectID, status SubjectStatus) (Subject, error) {
	if subjectID.IsZero() {
		return Subject{}, ErrAccountNotFound
	}
	if err := status.Validate(); err != nil {
		return Subject{}, err
	}
	subject, err := r.store.SetSubjectStatus(ctx, subjectID, status, r.now().UTC())
	if err != nil {
		return Subject{}, fmt.Errorf("set subject status: %w", err)
	}
	if err := r.recordAudit(ctx, SecurityEvent{
		Type:       SecurityEventSubjectStatusChanged,
		SubjectID:  subjectID,
		At:         r.now().UTC(),
		Attributes: map[string]string{"status": string(status)},
	}); err != nil {
		return Subject{}, err
	}

	return subject, nil
}

func (r *Runtime) issueSession(ctx context.Context, account Account, realm Realm, scope SessionScope) (TokenPair, error) {
	now := r.now().UTC()
	refresh, digest, err := r.secretCodec.Generate("refresh")
	if err != nil {
		return TokenPair{}, err
	}
	refreshExpiresAt := now.Add(r.refreshTTL)
	sessionExpiresAt := now.Add(r.sessionTTL)
	if refreshExpiresAt.Before(sessionExpiresAt) {
		sessionExpiresAt = refreshExpiresAt
	}
	session := Session{
		ID:              uuid.NewString(),
		SubjectID:       account.Subject.ID,
		Realm:           realm,
		Scope:           scope,
		SecurityVersion: account.Subject.SecurityVersion,
		CreatedAt:       now,
		ExpiresAt:       sessionExpiresAt,
	}
	if err := r.store.CreateSession(ctx, SessionRecord{
		Session:          session,
		FamilyID:         uuid.NewString(),
		RefreshSelector:  refresh.selector,
		RefreshDigest:    digest,
		RefreshExpiresAt: refreshExpiresAt,
	}); err != nil {
		return TokenPair{}, fmt.Errorf("create auth session: %w", err)
	}
	accessExpiresAt := now.Add(r.accessTTL)
	accessToken, err := r.jwt.Sign(ctx, account, session, accessExpiresAt, r.claims)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     refresh.raw,
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
		Session:          session,
	}, nil
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
