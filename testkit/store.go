package testkit

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
)

type Store struct {
	audits           []goauth.SecurityEvent
	mu               sync.Mutex
	accounts         map[string]goauth.Account
	retired          map[string]time.Time
	identifiers      map[string]string
	localIdentifiers map[string]goauth.Identifier
	passwords        map[string]string
	passwordPolicies map[string]goauth.PasswordInputPolicy
	links            map[string]goauth.IdentityLink
	sessions         map[string]goauth.Session
	families         map[string]*refreshFamily
	refresh          map[string]*refreshToken
	resets           map[string]*passwordReset
	challenges       map[string][]*emailChallenge
	emailChanges     map[string][]*emailChange
	rateEvents       map[string][]time.Time
}

type refreshFamily struct {
	ID         string
	SessionID  string
	SubjectID  goauth.SubjectID
	RevokedAt  *time.Time
	ReplayedAt *time.Time
}

type refreshToken struct {
	FamilyID   string
	Digest     goauth.SecretDigest
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

type passwordReset struct {
	SubjectID  goauth.SubjectID
	Digest     goauth.SecretDigest
	ExpiresAt  time.Time
	ConsumedAt *time.Time
}

type emailChallenge struct {
	Record     goauth.EmailChallengeRecord
	Attempts   int
	VerifiedAt *time.Time
}

type emailChange struct {
	Record     goauth.EmailChangeRecord
	Attempts   int
	ConsumedAt *time.Time
}

func NewStore() *Store {
	return &Store{
		accounts:         make(map[string]goauth.Account),
		retired:          make(map[string]time.Time),
		identifiers:      make(map[string]string),
		localIdentifiers: make(map[string]goauth.Identifier),
		passwords:        make(map[string]string),
		passwordPolicies: make(map[string]goauth.PasswordInputPolicy),
		links:            make(map[string]goauth.IdentityLink),
		sessions:         make(map[string]goauth.Session),
		families:         make(map[string]*refreshFamily),
		refresh:          make(map[string]*refreshToken),
		resets:           make(map[string]*passwordReset),
		challenges:       make(map[string][]*emailChallenge),
		emailChanges:     make(map[string][]*emailChange),
		rateEvents:       make(map[string][]time.Time),
	}
}

func (s *Store) FindAccount(
	ctx context.Context,
	identifier goauth.IdentifierInput,
) (goauth.Account, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	subjectKey, found := s.identifiers[identifierKey(identifier.Scheme, identifier.Value)]
	if !found {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}

	return cloneAccount(s.accounts[subjectKey]), nil
}

func (s *Store) ResolveIdentityLink(
	ctx context.Context,
	issuer string,
	externalSubject string,
) (goauth.Account, goauth.IdentityLink, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	link, found := s.links[identityKey(issuer, externalSubject)]
	if !found {
		return goauth.Account{}, goauth.IdentityLink{}, goauth.ErrIdentityLinkNotFound
	}

	return cloneAccount(s.accounts[link.SubjectID.String()]), link, nil
}

func (s *Store) CreateSSOAccount(
	ctx context.Context,
	record goauth.SSOAccountRecord,
) (goauth.Account, goauth.IdentityLink, error) {
	if record.Link.SubjectID != record.Account.Subject.ID {
		return goauth.Account{}, goauth.IdentityLink{}, errors.New("SSO identity link must belong to the created subject")
	}
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.accounts[record.Account.Subject.ID.String()]; exists {
		return goauth.Account{}, goauth.IdentityLink{}, goauth.ErrIdentifierAlreadyExists
	}
	identifier := identifierKey(record.Account.PrimaryEmail.Scheme, record.Account.PrimaryEmail.NormalizedValue)
	if _, found := s.identifiers[identifier]; found {
		return goauth.Account{}, goauth.IdentityLink{}, goauth.ErrIdentifierAlreadyExists
	}
	linkKey := identityKey(record.Link.Issuer, record.Link.ExternalSubject)
	if _, found := s.links[linkKey]; found {
		return goauth.Account{}, goauth.IdentityLink{}, goauth.ErrIdentityLinkConflict
	}
	subjectKey := record.Account.Subject.ID.String()
	account := cloneAccount(record.Account)
	s.accounts[subjectKey] = account
	s.identifiers[identifier] = subjectKey
	s.links[linkKey] = record.Link

	return cloneAccount(account), record.Link, nil
}

func (s *Store) LinkIdentity(ctx context.Context, link goauth.IdentityLink) (goauth.IdentityLink, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, found := s.accounts[link.SubjectID.String()]; !found {
		return goauth.IdentityLink{}, goauth.ErrAccountNotFound
	}
	if _, retired := s.retired[link.SubjectID.String()]; retired {
		return goauth.IdentityLink{}, goauth.ErrSubjectRetired
	}
	key := identityKey(link.Issuer, link.ExternalSubject)
	if existing, found := s.links[key]; found {
		if existing.SubjectID == link.SubjectID {
			return existing, nil
		}
		return goauth.IdentityLink{}, goauth.ErrIdentityLinkConflict
	}
	s.links[key] = link

	return link, nil
}

func (s *Store) CreateLocalAccount(
	ctx context.Context,
	record goauth.LocalAccountRecord,
) (goauth.Account, error) {
	return s.createLocalAccount(ctx, record, record.Account.PrimaryEmail)
}

func (s *Store) CreateLocalIdentity(ctx context.Context, record goauth.LocalIdentityRecord) (goauth.Account, error) {
	return s.createLocalAccount(ctx, record.LocalAccountRecord, record.Identifier)
}

func (s *Store) createLocalAccount(
	ctx context.Context, record goauth.LocalAccountRecord, identifier goauth.Identifier,
) (goauth.Account, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.accounts[record.Account.Subject.ID.String()]; exists {
		return goauth.Account{}, goauth.ErrIdentifierAlreadyExists
	}
	identifierKey := identifierKey(identifier.Scheme, identifier.NormalizedValue)
	if _, exists := s.identifiers[identifierKey]; exists {
		return goauth.Account{}, goauth.ErrIdentifierAlreadyExists
	}
	subjectKey := record.Account.Subject.ID.String()
	account := cloneAccount(record.Account)
	s.accounts[subjectKey] = account
	s.identifiers[identifierKey] = subjectKey
	s.passwords[subjectKey] = record.PasswordPHC
	s.passwordPolicies[subjectKey] = record.PasswordInputPolicy
	if identifier.Scheme != goauth.IdentifierSchemeEmail {
		s.localIdentifiers[localIdentifierKey(record.Account.Subject.ID, identifier.Scheme)] = cloneLocalIdentifier(identifier)
	}

	return cloneAccount(account), nil
}

func (s *Store) FindLocalAccount(
	ctx context.Context,
	identifier goauth.IdentifierInput,
) (goauth.LocalAccountRecord, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	subjectKey, found := s.identifiers[identifierKey(identifier.Scheme, identifier.Value)]
	if !found {
		return goauth.LocalAccountRecord{}, goauth.ErrAccountNotFound
	}
	password, found := s.passwords[subjectKey]
	if !found {
		return goauth.LocalAccountRecord{}, goauth.ErrAccountNotFound
	}

	return goauth.LocalAccountRecord{
		Account: cloneAccount(s.accounts[subjectKey]), PasswordPHC: password, PasswordInputPolicy: s.passwordPolicies[subjectKey],
	}, nil
}

func (s *Store) GetLocalAccount(
	ctx context.Context,
	subjectID goauth.SubjectID,
) (goauth.LocalAccountRecord, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	subjectKey := subjectID.String()
	account, found := s.accounts[subjectKey]
	if !found {
		return goauth.LocalAccountRecord{}, goauth.ErrAccountNotFound
	}
	password, found := s.passwords[subjectKey]
	if !found {
		return goauth.LocalAccountRecord{}, goauth.ErrAccountNotFound
	}

	return goauth.LocalAccountRecord{
		Account: cloneAccount(account), PasswordPHC: password, PasswordInputPolicy: s.passwordPolicies[subjectKey],
	}, nil
}

func (s *Store) GetAccount(ctx context.Context, subjectID goauth.SubjectID) (goauth.Account, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	account, found := s.accounts[subjectID.String()]
	if !found {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}

	return cloneAccount(account), nil
}

func (s *Store) UpdateBasicProfile(
	ctx context.Context,
	subjectID goauth.SubjectID,
	profile goauth.BasicProfile,
	now time.Time,
) (goauth.Account, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	key := subjectID.String()
	account, found := s.accounts[key]
	if !found {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}
	account.Profile = profile
	account.Subject.UpdatedAt = now
	s.accounts[key] = account

	return cloneAccount(account), nil
}

func (s *Store) ChangePassword(
	ctx context.Context,
	request goauth.PasswordChangeStoreRequest,
) (goauth.PasswordChangeStoreResult, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	key := request.SubjectID.String()
	account, found := s.accounts[key]
	if !found {
		return goauth.PasswordChangeStoreResult{Status: goauth.PasswordChangeStoreMissing}, nil
	}
	if _, retired := s.retired[key]; retired {
		return goauth.PasswordChangeStoreResult{}, goauth.ErrSubjectRetired
	}
	current, found := s.passwords[key]
	if !found {
		return goauth.PasswordChangeStoreResult{Status: goauth.PasswordChangeStoreMissing}, nil
	}
	if current != request.ExpectedPasswordPHC {
		return goauth.PasswordChangeStoreResult{Status: goauth.PasswordChangeStoreConflict}, nil
	}
	if account.Subject.Status != goauth.SubjectStatusActive {
		return goauth.PasswordChangeStoreResult{}, goauth.ErrAccountUnavailable
	}
	s.passwords[key] = request.NewPasswordPHC
	s.passwordPolicies[key] = goauth.PasswordInputPolicyUnicode
	account.Subject.SecurityVersion++
	account.Subject.UpdatedAt = request.Now
	s.accounts[key] = account
	s.revokeSubjectSecurityLocked(request.SubjectID, request.Now)
	s.invalidatePasswordResetsLocked(request.SubjectID, request.Now)

	return goauth.PasswordChangeStoreResult{
		Status:  goauth.PasswordChangeStoreSucceeded,
		Account: cloneAccount(account),
	}, nil
}

func (s *Store) CreateSession(ctx context.Context, record goauth.SessionRecord) error {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	account, found := s.accounts[record.Session.SubjectID.String()]
	if !found || account.Subject.Status != goauth.SubjectStatusActive {
		return goauth.ErrAccountUnavailable
	}
	if account.Subject.SecurityVersion != record.Session.SecurityVersion {
		return goauth.ErrSecurityVersionMismatch
	}
	// Scope was signed before this lock. Verification may promote existing
	// sessions, but must never leave a newly inserted confirmation session behind.
	if account.EmailVerified() != (record.Session.Scope == goauth.SessionScopeAuthenticated) {
		return goauth.ErrSecurityVersionMismatch
	}
	if _, exists := s.sessions[record.Session.ID]; exists {
		return errors.New("duplicate test session")
	}
	s.sessions[record.Session.ID] = record.Session
	s.families[record.FamilyID] = &refreshFamily{
		ID:        record.FamilyID,
		SessionID: record.Session.ID,
		SubjectID: record.Session.SubjectID,
	}
	s.refresh[record.RefreshSelector] = &refreshToken{
		FamilyID:  record.FamilyID,
		Digest:    cloneDigest(record.RefreshDigest),
		ExpiresAt: record.RefreshExpiresAt,
	}

	return nil
}

func (s *Store) PeekRefresh(ctx context.Context, request goauth.RefreshRotationRequest) (goauth.RefreshRotationResult, error) {
	return s.rotateRefresh(ctx, request, true)
}

func (s *Store) RotateRefresh(ctx context.Context, request goauth.RefreshRotationRequest) (goauth.RefreshRotationResult, error) {
	return s.rotateRefresh(ctx, request, false)
}

func (s *Store) rotateRefresh(
	ctx context.Context,
	request goauth.RefreshRotationRequest,
	peek bool,
) (goauth.RefreshRotationResult, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	token, found := s.refresh[request.CurrentSelector]
	if !found {
		return goauth.RefreshRotationResult{Status: goauth.RefreshRotationInvalid}, nil
	}
	family := s.families[token.FamilyID]
	session := s.sessions[family.SessionID]
	account := s.accounts[family.SubjectID.String()]
	result := goauth.RefreshRotationResult{
		Account:  cloneAccount(account),
		Session:  session,
		FamilyID: family.ID,
	}
	if token.Digest.KeyID != request.CurrentDigest.KeyID || !hmac.Equal(token.Digest.Digest, request.CurrentDigest.Digest) {
		result.Status = goauth.RefreshRotationInvalid
		return result, nil
	}
	if token.ConsumedAt != nil {
		if peek {
			result.Status = goauth.RefreshRotationReplayed
			return result, nil
		}
		now := request.Now
		family.RevokedAt = &now
		family.ReplayedAt = &now
		session.RevokedAt = &now
		s.sessions[session.ID] = session
		result.Session = session
		result.Status = goauth.RefreshRotationReplayed
		return result, nil
	}
	if !request.Now.Before(token.ExpiresAt) || !request.Now.Before(session.ExpiresAt) {
		result.Status = goauth.RefreshRotationExpired
		return result, nil
	}
	if family.RevokedAt != nil || session.RevokedAt != nil ||
		account.Subject.Status != goauth.SubjectStatusActive ||
		account.Subject.SecurityVersion != session.SecurityVersion {
		result.Status = goauth.RefreshRotationRevoked
		return result, nil
	}
	if request.ExpectedSecurityVersion != 0 && (account.Subject.SecurityVersion != request.ExpectedSecurityVersion ||
		account.PrimaryEmail.NormalizedValue != request.ExpectedNormalizedEmail ||
		account.EmailVerified() != request.ExpectedEmailVerified) {
		result.Status = goauth.RefreshRotationRevoked
		return result, nil
	}
	if peek {
		result.Status = goauth.RefreshRotationSucceeded
		return result, nil
	}
	if request.NextSelector == "" || len(request.NextDigest.Digest) != 32 {
		result.Status = goauth.RefreshRotationInvalid
		return result, nil
	}
	now := request.Now
	token.ConsumedAt = &now
	s.refresh[request.NextSelector] = &refreshToken{
		FamilyID:  family.ID,
		Digest:    cloneDigest(request.NextDigest),
		ExpiresAt: request.NextExpiresAt,
	}
	result.Status = goauth.RefreshRotationSucceeded

	return result, nil
}

func (s *Store) IntrospectSession(ctx context.Context, sessionID string) (goauth.SessionSecurity, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	session, found := s.sessions[sessionID]
	if !found {
		return goauth.SessionSecurity{}, goauth.ErrSessionRevoked
	}
	account := s.accounts[session.SubjectID.String()]

	return goauth.SessionSecurity{
		Session:        session,
		SubjectStatus:  account.Subject.Status,
		CurrentVersion: account.Subject.SecurityVersion,
	}, nil
}

func (s *Store) RevokeSession(
	ctx context.Context,
	subjectID goauth.SubjectID,
	sessionID string,
	now time.Time,
) (bool, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	session, found := s.sessions[sessionID]
	if !found || session.SubjectID != subjectID || session.RevokedAt != nil {
		return false, nil
	}
	revokedAt := now
	session.RevokedAt = &revokedAt
	s.sessions[sessionID] = session
	for _, family := range s.families {
		if family.SessionID == sessionID {
			value := now
			family.RevokedAt = &value
		}
	}

	return true, nil
}

func (s *Store) RevokeSubjectSessions(
	ctx context.Context,
	subjectID goauth.SubjectID,
	now time.Time,
) (int64, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	key := subjectID.String()
	account, found := s.accounts[key]
	if !found {
		return 0, nil
	}
	account.Subject.SecurityVersion++
	account.Subject.UpdatedAt = now
	s.accounts[key] = account
	return s.revokeSubjectSecurityLocked(subjectID, now), nil
}

func (s *Store) revokeSubjectSecurityLocked(subjectID goauth.SubjectID, now time.Time) int64 {
	var revoked int64
	for sessionID, session := range s.sessions {
		if session.SubjectID != subjectID {
			continue
		}
		if session.RevokedAt == nil {
			revoked++
		}
		value := now
		session.RevokedAt = &value
		s.sessions[sessionID] = session
	}
	for _, family := range s.families {
		if family.SubjectID == subjectID {
			value := now
			family.RevokedAt = &value
		}
	}
	for _, records := range s.emailChanges {
		for _, record := range records {
			if record.Record.SubjectID == subjectID && record.ConsumedAt == nil {
				value := now
				record.ConsumedAt = &value
			}
		}
	}
	for _, records := range s.challenges {
		for _, record := range records {
			if record.Record.SubjectID == subjectID && record.VerifiedAt == nil {
				record.Attempts = record.Record.MaxAttempts
			}
		}
	}

	return revoked
}

func (s *Store) SetSubjectStatus(
	ctx context.Context,
	subjectID goauth.SubjectID,
	status goauth.SubjectStatus,
	now time.Time,
) (goauth.Subject, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	account, found := s.accounts[subjectID.String()]
	if !found {
		return goauth.Subject{}, goauth.ErrAccountNotFound
	}
	if _, retired := s.retired[subjectID.String()]; retired {
		return goauth.Subject{}, goauth.ErrSubjectRetired
	}
	if account.Subject.Status == status {
		return account.Subject, nil
	}
	account.Subject.Status = status
	account.Subject.SecurityVersion++
	account.Subject.UpdatedAt = now
	s.accounts[subjectID.String()] = account
	s.revokeSubjectSecurityLocked(subjectID, now)
	s.invalidatePasswordResetsLocked(subjectID, now)

	return account.Subject, nil
}

func (s *Store) CreatePasswordReset(ctx context.Context, record goauth.PasswordResetRecord) error {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	account, found := s.accounts[record.SubjectID.String()]
	if !found || account.Subject.Status != goauth.SubjectStatusActive ||
		account.Subject.SecurityVersion != record.ExpectedSecurityVersion ||
		account.PrimaryEmail.NormalizedValue != record.ExpectedNormalizedEmail {
		return goauth.ErrAccountNotFound
	}

	for _, stored := range s.resets {
		if stored.SubjectID == record.SubjectID && stored.ConsumedAt == nil {
			value := record.CreatedAt
			stored.ConsumedAt = &value
		}
	}
	s.resets[record.Selector] = &passwordReset{
		SubjectID: record.SubjectID,
		Digest:    cloneDigest(record.Digest),
		ExpiresAt: record.ExpiresAt,
	}

	return nil
}

func (s *Store) ConsumePasswordReset(
	ctx context.Context,
	request goauth.PasswordResetConsumeRequest,
) (goauth.PasswordResetConsumeResult, error) {
	return s.consumePasswordReset(ctx, request, nil)
}

func (s *Store) consumePasswordReset(
	ctx context.Context, request goauth.PasswordResetConsumeRequest,
	prepare func(context.Context, goauth.Account) (string, error),
) (goauth.PasswordResetConsumeResult, error) {
	started := time.Now()
	origin := request.Now
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	record, found := s.resets[request.Selector]
	if !found || record.Digest.KeyID != request.Digest.KeyID || !hmac.Equal(record.Digest.Digest, request.Digest.Digest) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
	account := s.accounts[record.SubjectID.String()]
	if account.Subject.Status != goauth.SubjectStatusActive {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}
	if record.ConsumedAt != nil {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetUsed}, nil
	}
	if prepare != nil {
		request.Now = authclock.Now(ctx, origin, started)
	}
	if !request.Now.Before(record.ExpiresAt) {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetExpired}, nil
	}
	if s.passwords[record.SubjectID.String()] == "" {
		return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetInvalid}, nil
	}

	if prepare != nil {
		// The outer transaction owns the original store mutex. Release only
		// the isolated working-copy mutex so host reads can join this context.
		s.mu.Unlock()
		preparedPHC, err := func() (string, error) {
			defer s.mu.Lock()
			return prepare(ctx, cloneAccount(account))
		}()
		if err != nil {
			return goauth.PasswordResetConsumeResult{}, err
		}
		if err := ctx.Err(); err != nil {
			return goauth.PasswordResetConsumeResult{}, err
		}
		if preparedPHC == "" {
			return goauth.PasswordResetConsumeResult{}, goauth.ErrInvalidPassword
		}
		request.PasswordPHC = preparedPHC
		request.Now = authclock.Now(ctx, origin, started)
		if !request.Now.Before(record.ExpiresAt) {
			return goauth.PasswordResetConsumeResult{Status: goauth.PasswordResetExpired}, nil
		}
	}
	s.passwords[record.SubjectID.String()] = request.PasswordPHC
	s.passwordPolicies[record.SubjectID.String()] = goauth.PasswordInputPolicyUnicode
	value := request.Now
	record.ConsumedAt = &value
	account.Subject.SecurityVersion++
	account.Subject.UpdatedAt = request.Now
	s.accounts[record.SubjectID.String()] = account
	s.revokeSubjectSecurityLocked(record.SubjectID, request.Now)
	s.invalidatePasswordResetsLocked(record.SubjectID, request.Now)

	return goauth.PasswordResetConsumeResult{
		Status:  goauth.PasswordResetConsumed,
		Account: cloneAccount(account),
	}, nil
}

func (s *Store) IssueEmailChallenge(
	ctx context.Context,
	record goauth.EmailChallengeRecord,
	limits goauth.EmailChallengeLimits,
) (goauth.EmailChallengeIssueResult, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, retired := s.retired[record.SubjectID.String()]; retired {
		return goauth.EmailChallengeIssueResult{}, goauth.ErrSubjectRetired
	}

	if record.ExpectedSecurityVersion > 0 || record.ExpectedNormalizedEmail != "" {
		account, ok := s.accounts[record.SubjectID.String()]
		if !ok {
			return goauth.EmailChallengeIssueResult{}, goauth.ErrAccountNotFound
		}
		if account.Subject.Status != goauth.SubjectStatusActive {
			return goauth.EmailChallengeIssueResult{}, goauth.ErrAccountUnavailable
		}
		if record.ExpectedSecurityVersion <= 0 || record.ExpectedNormalizedEmail == "" ||
			account.Subject.SecurityVersion != record.ExpectedSecurityVersion ||
			account.PrimaryEmail.ID != record.IdentifierID ||
			account.PrimaryEmail.NormalizedValue != record.ExpectedNormalizedEmail {
			return goauth.EmailChallengeIssueResult{}, goauth.ErrInvalidIdentifier
		}
	}

	key := challengeKey(record.SubjectID, record.Purpose)
	rateKey := rateBucketKey(record.RateDigest, "email_challenge:"+string(record.Purpose))
	events := s.rateEvents[rateKey]
	quota := evaluateEmailQuota(events, record.CreatedAt, limits)
	if quota.waiting {
		return goauth.EmailChallengeIssueResult{Status: goauth.EmailChallengeWait, RetryAt: quota.retryAt}, nil
	}
	if quota.hourly {
		return goauth.EmailChallengeIssueResult{Status: goauth.EmailChallengeHourlyLimit, RetryAt: quota.retryAt}, nil
	}
	if quota.daily {
		return goauth.EmailChallengeIssueResult{Status: goauth.EmailChallengeDailyLimit, RetryAt: quota.retryAt}, nil
	}
	s.rateEvents[rateKey] = append(events, record.CreatedAt)
	s.challenges[key] = append(s.challenges[key], &emailChallenge{Record: cloneChallengeRecord(record)})

	return goauth.EmailChallengeIssueResult{Status: goauth.EmailChallengeIssued}, nil
}

// TakeRateLimit admits an attempt outside any managed auth transaction.
// Auth writes may roll back; attempt accounting must not roll back with them.
func (s *Store) TakeRateLimit(
	ctx context.Context,
	request goauth.RateLimitRequest,
) (goauth.RateLimitResult, error) {
	if request.Action == "" || request.Limit <= 0 || request.Window <= 0 ||
		request.Bucket.KeyID == "" || len(request.Bucket.Digest) != 32 || request.Now.IsZero() {
		return goauth.RateLimitResult{}, errors.New("invalid test rate limit request")
	}
	if scope, ok := ctx.Value(storeScopeKey{}).(storeScope); ok &&
		(scope.original == s || scope.working == s) {
		// Check before locking: the outer transaction already holds s.mu.
		return goauth.RateLimitResult{}, goauth.ErrRateLimitTransactionUnsupported
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := rateBucketKey(request.Bucket, request.Action)
	events := s.rateEvents[key]
	cutoff := request.Now.Add(-request.Window)
	active := make([]time.Time, 0, len(events)+1)
	for _, occurredAt := range events {
		if !occurredAt.Before(cutoff) {
			active = append(active, occurredAt)
		}
	}
	if len(active) >= request.Limit {
		sort.Slice(active, func(i, j int) bool { return active[i].After(active[j]) })
		return goauth.RateLimitResult{RetryAt: active[request.Limit-1].Add(request.Window)}, nil
	}
	s.rateEvents[key] = append(active, request.Now)
	return goauth.RateLimitResult{Allowed: true}, nil
}

func (s *Store) VerifyEmailChallenge(
	ctx context.Context,
	request goauth.EmailChallengeVerifyRequest,
) (goauth.EmailChallengeVerifyResult, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, retired := s.retired[request.SubjectID.String()]; retired {
		return goauth.EmailChallengeVerifyResult{}, goauth.ErrSubjectRetired
	}

	key := challengeKey(request.SubjectID, request.Purpose)
	records := s.challenges[key]
	if len(records) == 0 {
		return goauth.EmailChallengeVerifyResult{Status: goauth.EmailChallengeInvalid}, nil
	}
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].Record.CreatedAt.Before(records[j].Record.CreatedAt)
	})
	record := records[len(records)-1]
	if record.VerifiedAt != nil {
		return goauth.EmailChallengeVerifyResult{
			Status:   goauth.EmailChallengeAlreadyVerified,
			Account:  cloneAccount(s.accounts[request.SubjectID.String()]),
			Attempts: record.Attempts,
		}, nil
	}
	if record.Attempts >= record.Record.MaxAttempts {
		return goauth.EmailChallengeVerifyResult{Status: goauth.EmailChallengeAttemptsUsed, Attempts: record.Attempts}, nil
	}
	if !request.Now.Before(record.Record.ExpiresAt) {
		return goauth.EmailChallengeVerifyResult{Status: goauth.EmailChallengeExpired, Attempts: record.Attempts}, nil
	}
	if !matchesDigest(record.Record.Digest, request.Digests) {
		record.Attempts++
		return goauth.EmailChallengeVerifyResult{Status: goauth.EmailChallengeInvalid, Attempts: record.Attempts}, nil
	}
	verifiedAt := request.Now
	record.VerifiedAt = &verifiedAt
	account := s.accounts[request.SubjectID.String()]
	account.PrimaryEmail.VerifiedAt = &verifiedAt
	account.PrimaryEmail.UpdatedAt = verifiedAt
	s.accounts[request.SubjectID.String()] = account
	for sessionID, session := range s.sessions {
		if session.SubjectID == request.SubjectID &&
			session.Realm == goauth.RealmUser &&
			session.Scope == goauth.SessionScopeConfirmation &&
			session.RevokedAt == nil {
			session.Scope = goauth.SessionScopeAuthenticated
			s.sessions[sessionID] = session
		}
	}

	return goauth.EmailChallengeVerifyResult{
		Status:   goauth.EmailChallengeVerified,
		Account:  cloneAccount(account),
		Attempts: record.Attempts,
	}, nil
}

func (s *Store) IssueEmailChange(
	ctx context.Context,
	record goauth.EmailChangeRecord,
	limits goauth.EmailChallengeLimits,
) (goauth.EmailChangeIssueResult, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, retired := s.retired[record.SubjectID.String()]; retired {
		return goauth.EmailChangeIssueResult{}, goauth.ErrSubjectRetired
	}

	account, found := s.accounts[record.SubjectID.String()]
	if !found {
		return goauth.EmailChangeIssueResult{}, goauth.ErrAccountNotFound
	}
	if account.PrimaryEmail.NormalizedValue == record.NewNormalizedValue {
		return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeSameValue}, nil
	}
	identifier := identifierKey(goauth.IdentifierSchemeEmail, record.NewNormalizedValue)
	if subjectKey, occupied := s.identifiers[identifier]; occupied && subjectKey != record.SubjectID.String() {
		return goauth.EmailChangeIssueResult{}, goauth.ErrIdentifierAlreadyExists
	}
	rateKey := rateBucketKey(record.RateDigest, "email_change")
	events := s.rateEvents[rateKey]
	quota := evaluateEmailQuota(events, record.CreatedAt, limits)
	if quota.waiting {
		return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeWait, RetryAt: quota.retryAt}, nil
	}
	if quota.hourly {
		return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeHourlyLimit, RetryAt: quota.retryAt}, nil
	}
	if quota.daily {
		return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeDailyLimit, RetryAt: quota.retryAt}, nil
	}
	now := record.CreatedAt
	for _, existing := range s.emailChanges[record.SubjectID.String()] {
		if existing.ConsumedAt == nil {
			existing.ConsumedAt = &now
		}
	}
	s.rateEvents[rateKey] = append(events, record.CreatedAt)
	s.emailChanges[record.SubjectID.String()] = append(
		s.emailChanges[record.SubjectID.String()],
		&emailChange{Record: cloneEmailChangeRecord(record)},
	)

	return goauth.EmailChangeIssueResult{Status: goauth.EmailChangeIssued}, nil
}

func (s *Store) GetPendingEmailChange(
	ctx context.Context,
	subjectID goauth.SubjectID,
	now time.Time,
) (goauth.PendingEmailChange, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	record := s.latestPendingEmailChangeLocked(subjectID)
	if record == nil || !now.Before(record.Record.ExpiresAt) {
		return goauth.PendingEmailChange{}, goauth.ErrEmailChangeNotFound
	}

	return goauth.PendingEmailChange{
		ID:              record.Record.ID,
		SubjectID:       subjectID,
		NewDisplayValue: record.Record.NewDisplayValue,
		Attempts:        record.Attempts,
		MaxAttempts:     record.Record.MaxAttempts,
		CreatedAt:       record.Record.CreatedAt,
		ExpiresAt:       record.Record.ExpiresAt,
	}, nil
}

func (s *Store) VerifyEmailChange(
	ctx context.Context,
	request goauth.EmailChangeVerifyRequest,
) (goauth.EmailChangeVerifyResult, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, retired := s.retired[request.SubjectID.String()]; retired {
		return goauth.EmailChangeVerifyResult{}, goauth.ErrSubjectRetired
	}

	record := s.latestPendingEmailChangeLocked(request.SubjectID)
	if record == nil {
		return goauth.EmailChangeVerifyResult{Status: goauth.EmailChangeNotFound}, nil
	}
	if record.Attempts >= record.Record.MaxAttempts {
		return goauth.EmailChangeVerifyResult{
			Status:   goauth.EmailChangeAttemptsUsed,
			Attempts: record.Attempts,
		}, nil
	}
	if !request.Now.Before(record.Record.ExpiresAt) {
		return goauth.EmailChangeVerifyResult{
			Status:   goauth.EmailChangeExpired,
			Attempts: record.Attempts,
		}, nil
	}
	if !matchesDigest(record.Record.Digest, request.Digests) {
		record.Attempts++
		return goauth.EmailChangeVerifyResult{
			Status:   goauth.EmailChangeInvalid,
			Attempts: record.Attempts,
		}, nil
	}
	account := s.accounts[request.SubjectID.String()]
	delete(s.identifiers, identifierKey(account.PrimaryEmail.Scheme, account.PrimaryEmail.NormalizedValue))
	s.identifiers[identifierKey(goauth.IdentifierSchemeEmail, record.Record.NewNormalizedValue)] = request.SubjectID.String()
	verifiedAt := request.Now
	account.PrimaryEmail.DisplayValue = record.Record.NewDisplayValue
	account.PrimaryEmail.NormalizedValue = record.Record.NewNormalizedValue
	account.PrimaryEmail.VerifiedAt = &verifiedAt
	account.PrimaryEmail.UpdatedAt = request.Now
	account.Subject.SecurityVersion++
	account.Subject.UpdatedAt = request.Now
	s.accounts[request.SubjectID.String()] = account
	consumedAt := request.Now
	record.ConsumedAt = &consumedAt
	s.revokeSubjectSecurityLocked(request.SubjectID, request.Now)
	s.invalidatePasswordResetsLocked(request.SubjectID, request.Now)
	for _, challenge := range s.challenges[challengeKey(request.SubjectID, goauth.EmailChallengePurposeVerification)] {
		if challenge.VerifiedAt == nil {
			challenge.Attempts = challenge.Record.MaxAttempts
		}
	}

	return goauth.EmailChangeVerifyResult{
		Status:   goauth.EmailChangeVerified,
		Account:  cloneAccount(account),
		Attempts: record.Attempts,
	}, nil
}

func (s *Store) invalidatePasswordResetsLocked(subjectID goauth.SubjectID, now time.Time) {
	for _, record := range s.resets {
		if record.SubjectID == subjectID && record.ConsumedAt == nil {
			value := now
			record.ConsumedAt = &value
		}
	}
}

func (s *Store) latestPendingEmailChangeLocked(subjectID goauth.SubjectID) *emailChange {
	records := s.emailChanges[subjectID.String()]
	for index := len(records) - 1; index >= 0; index-- {
		if records[index].ConsumedAt == nil {
			return records[index]
		}
	}

	return nil
}

func (s *Store) ChallengeAttempts(subjectID goauth.SubjectID, purpose goauth.EmailChallengePurpose) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	records := s.challenges[challengeKey(subjectID, purpose)]
	if len(records) == 0 {
		return 0
	}

	return records[len(records)-1].Attempts
}

func identifierKey(scheme goauth.IdentifierScheme, value string) string {
	return string(scheme) + ":" + value
}

func challengeKey(subjectID goauth.SubjectID, purpose goauth.EmailChallengePurpose) string {
	return subjectID.String() + ":" + string(purpose)
}

func identityKey(issuer, externalSubject string) string {
	return issuer + ":" + externalSubject
}

func rateBucketKey(bucket goauth.SecretDigest, action string) string {
	return bucket.KeyID + ":" + hex.EncodeToString(bucket.Digest) + ":" + action
}

func cloneAccount(account goauth.Account) goauth.Account {
	clone := account
	if account.PrimaryEmail.VerifiedAt != nil {
		value := *account.PrimaryEmail.VerifiedAt
		clone.PrimaryEmail.VerifiedAt = &value
	}

	return clone
}

func cloneDigest(digest goauth.SecretDigest) goauth.SecretDigest {
	return goauth.SecretDigest{KeyID: digest.KeyID, Digest: append([]byte(nil), digest.Digest...)}
}

func cloneChallengeRecord(record goauth.EmailChallengeRecord) goauth.EmailChallengeRecord {
	clone := record
	clone.Digest = cloneDigest(record.Digest)
	clone.RateDigest = cloneDigest(record.RateDigest)

	return clone
}

func cloneEmailChangeRecord(record goauth.EmailChangeRecord) goauth.EmailChangeRecord {
	clone := record
	clone.Digest = cloneDigest(record.Digest)
	clone.RateDigest = cloneDigest(record.RateDigest)

	return clone
}

func matchesDigest(stored goauth.SecretDigest, candidates []goauth.SecretDigest) bool {
	for _, candidate := range candidates {
		if candidate.KeyID == stored.KeyID && hmac.Equal(candidate.Digest, stored.Digest) {
			return true
		}
	}

	return false
}

var _ goauth.RuntimeStore = (*Store)(nil)

func (s *Store) LockAccount(ctx context.Context, id goauth.SubjectID) (goauth.Account, error) {
	if s.scoped(ctx) == s {
		return goauth.Account{}, errors.New("LockAccount requires AuthTransaction")
	}
	return s.GetAccount(ctx, id)
}

func (s *Store) RecordSecurityEvent(ctx context.Context, event goauth.SecurityEvent) error {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audits = append(s.audits, event)
	return nil
}
