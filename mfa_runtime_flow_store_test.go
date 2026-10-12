package goauth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const (
	mfaFlowPassword = "MFA-runtime-fixture-password-1" //nolint:gosec // G101: Public synthetic fixture, not a real password.
	mfaFlowEmail    = "mfa-runtime@example.test"
	mfaFlowSecret   = "JBSWY3DPEHPK3PXP" //nolint:gosec // G101: Public synthetic test TOTP secret, never a real credential.
)

const (
	mfaFaultTakeAttempt      = "take_attempt"
	mfaFaultReplaceFactor    = "replace_factor"
	mfaCaseExpiryAfterCommit = "expiry after commit"
	mfaFaultConsumePending   = "consume_pending"
	mfaFaultReplaceRecovery  = "replace_recovery"
	mfaEventEnrolled         = "mfa.enrolled"
	mfaFaultEnsureFactor     = "ensure_factor"
	mfaFaultAdvanceStep      = "advance_step"
	mfaFaultCreateSession    = "create_session"
	mfaHashPrefix            = "fixture:"
	mfaCaseSecurityVersion   = "security version"
	mfaCaseBinding           = "binding"
	mfaCaseExpiry            = "expiry"
	mfaCaseWrongPassword     = "wrong password"
	mfaFaultLockFactor       = "lock_factor"
	mfaCaseEmptyBinding      = "empty binding"
	mfaCaseExpired           = "expired"
	mfaInvalidValue          = "invalid"
	mfaCaseCommitError       = "commit error"
	mfaCaseRateLimited       = "rate limited"
	mfaFaultInvalidate       = "invalidate"
)

var errMFAFlowCommit = errors.New("MFA fixture commit failed")

// mfaFlowState is copied together with testkit's account/session/audit snapshot.
// A callback error never leaks MFA attempts, factor changes, or session records.
type mfaFlowState struct {
	factor     goauth.MFAFactorRecord
	pending    map[string]goauth.MFALoginPending
	enrollment goauth.MFAEnrollmentRecord
	recovery   map[string]bool
	admissions map[string]goauth.MFASessionAdmission
	sessions   []goauth.SessionRecord
	audits     []goauth.SecurityEvent
	attempts   int
}

func (s mfaFlowState) clone() mfaFlowState {
	c := s
	c.factor.Ciphertext = bytes.Clone(s.factor.Ciphertext)
	c.pending = make(map[string]goauth.MFALoginPending, len(s.pending))
	for id, pending := range s.pending {
		pending.Setup = mfaFlowCloneSetup(pending.Setup)
		c.pending[id] = pending
	}
	c.enrollment.Ciphertext = bytes.Clone(s.enrollment.Ciphertext)
	c.recovery = maps.Clone(s.recovery)
	c.admissions = maps.Clone(s.admissions)
	c.sessions = slices.Clone(s.sessions)
	c.audits = slices.Clone(s.audits)
	return c
}

func mfaFlowCloneSetup(setup goauth.MFALoginSetup) goauth.MFALoginSetup {
	setup.Ciphertext = bytes.Clone(setup.Ciphertext)
	digests := make([][]byte, len(setup.RecoveryDigests))
	for i, digest := range setup.RecoveryDigests {
		digests[i] = bytes.Clone(digest)
	}
	if setup.RecoveryDigests != nil {
		setup.RecoveryDigests = digests
	}
	return setup
}

type mfaFlowScopeKey struct{}

type mfaFlowScope struct {
	store *mfaFlowStore
	state *mfaFlowState
}

// The fake is intentionally single-threaded: interleavings are scheduled by
// beforeOwned instead of sleeps. testkit owns actual account/session transactions.
type mfaFlowStore struct {
	*testkit.Store
	state            mfaFlowState
	faults           map[string]error
	reject           map[string]bool
	attemptLimit     int
	owned            int
	failCommitAt     int
	unknownCommitAt  int
	commitErr        error
	beforeOwned      func(int)
	afterOwnedCommit func(int)
}

func (s *mfaFlowStore) readState(ctx context.Context) *mfaFlowState {
	if scope, ok := ctx.Value(mfaFlowScopeKey{}).(mfaFlowScope); ok {
		if scope.store != s {
			panic("MFA fixture received a foreign transaction")
		}
		return scope.state
	}
	return &s.state
}

func (s *mfaFlowStore) writeState(ctx context.Context) *mfaFlowState {
	if _, ok := ctx.Value(mfaFlowScopeKey{}).(mfaFlowScope); !ok {
		panic("MFA fixture mutation escaped its transaction")
	}
	return s.readState(ctx)
}

func (s *mfaFlowStore) InAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	if _, ok := ctx.Value(mfaFlowScopeKey{}).(mfaFlowScope); ok {
		s.writeState(ctx)
		return fn(ctx)
	}
	return s.transaction(ctx, fn, 0)
}

func (s *mfaFlowStore) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	if _, ok := ctx.Value(mfaFlowScopeKey{}).(mfaFlowScope); ok {
		return goauth.ErrMFAUnavailable
	}
	s.owned++
	sequence := s.owned
	if s.beforeOwned != nil {
		s.beforeOwned(sequence)
	}
	return s.transaction(ctx, fn, sequence)
}

func (s *mfaFlowStore) transaction(ctx context.Context, fn func(context.Context) error, sequence int) error {
	working := s.state.clone()
	err := s.Store.InAuthTransaction(ctx, func(txctx context.Context) error {
		txctx = context.WithValue(txctx, mfaFlowScopeKey{}, mfaFlowScope{store: s, state: &working})
		if err := fn(txctx); err != nil {
			return err
		}
		if sequence > 0 && sequence == s.failCommitAt {
			return s.commitErr
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.state = working
	if sequence > 0 && s.afterOwnedCommit != nil {
		s.afterOwnedCommit(sequence)
	}
	// Model a committed-but-unacknowledged outcome separately from rollback.
	if sequence > 0 && sequence == s.unknownCommitAt {
		return s.commitErr
	}
	return nil
}

func (s *mfaFlowStore) LockMFAFactor(ctx context.Context, _ goauth.SubjectID) (goauth.MFAFactorRecord, error) {
	factor := s.writeState(ctx).factor
	factor.Ciphertext = bytes.Clone(factor.Ciphertext)
	return factor, s.faults[mfaFaultLockFactor]
}

func (s *mfaFlowStore) EnsureMFAFactor(ctx context.Context, subject goauth.SubjectID) (goauth.MFAFactorRecord, error) {
	if err := s.faults[mfaFaultEnsureFactor]; err != nil {
		return goauth.MFAFactorRecord{}, err
	}
	state := s.writeState(ctx)
	if state.factor.ID == "" {
		state.factor = goauth.MFAFactorRecord{ID: mfaFlowID(1), Revision: 1, LastStep: -1}
	}
	return s.LockMFAFactor(ctx, subject)
}

func (s *mfaFlowStore) LocalMFARequired(ctx context.Context, _ goauth.SubjectID) (bool, error) {
	return s.readState(ctx).factor.Enabled, s.faults["local_required"]
}

func (s *mfaFlowStore) TakeMFAAttempt(ctx context.Context, _ goauth.SubjectID) (bool, error) {
	if err := s.faults[mfaFaultTakeAttempt]; err != nil {
		return false, err
	}
	state := s.writeState(ctx)
	if state.attempts >= s.attemptLimit {
		return false, nil
	}
	state.attempts++
	return true, nil
}

func (s *mfaFlowStore) AdvanceMFAStep(ctx context.Context, _ goauth.SubjectID,
	factorID string, revision, previous, next int64,
) (bool, error) {
	if err := s.faults[mfaFaultAdvanceStep]; err != nil {
		return false, err
	}
	state := s.writeState(ctx)
	factor := state.factor
	if s.reject[mfaFaultAdvanceStep] || !factor.Enabled || factor.ID != factorID ||
		factor.Revision != revision || factor.LastStep != previous || next <= previous {
		return false, nil
	}
	state.factor.LastStep = next
	return true, nil
}

func (s *mfaFlowStore) ConsumeMFARecovery(ctx context.Context, _ goauth.SubjectID,
	factorID string, revision int64, digest []byte,
) (bool, error) {
	if err := s.faults["consume_recovery"]; err != nil {
		return false, err
	}
	state := s.writeState(ctx)
	if s.reject["consume_recovery"] || !state.factor.Enabled || state.factor.ID != factorID ||
		state.factor.Revision != revision || !state.recovery[string(digest)] {
		return false, nil
	}
	delete(state.recovery, string(digest))
	return true, nil
}

func (s *mfaFlowStore) FindMFALoginSubject(ctx context.Context, id string) (goauth.SubjectID, error) {
	if err := s.faults["find_pending"]; err != nil {
		return goauth.NilSubjectID, err
	}
	pending, ok := s.readState(ctx).pending[id]
	if !ok {
		return goauth.NilSubjectID, goauth.ErrMFALoginDenied
	}
	return pending.SubjectID, nil
}

func (s *mfaFlowStore) CreateMFALogin(ctx context.Context, pending goauth.MFALoginPending) error {
	if err := s.faults["create_pending"]; err != nil {
		return err
	}
	state := s.writeState(ctx)
	if _, exists := state.pending[pending.ID]; exists {
		return goauth.ErrMFALoginDenied
	}
	for id, current := range state.pending {
		if current.SubjectID == pending.SubjectID && current.Realm == pending.Realm {
			delete(state.pending, id)
		}
	}
	state.pending[pending.ID] = pending
	return nil
}

func (s *mfaFlowStore) LockMFALogin(ctx context.Context, id string) (goauth.MFALoginPending, error) {
	if err := s.faults["lock_pending"]; err != nil {
		return goauth.MFALoginPending{}, err
	}
	pending, ok := s.writeState(ctx).pending[id]
	if !ok {
		return goauth.MFALoginPending{}, goauth.ErrMFALoginDenied
	}
	pending.Setup = mfaFlowCloneSetup(pending.Setup)
	return pending, nil
}

func (s *mfaFlowStore) ConsumeMFALogin(ctx context.Context, pending goauth.MFALoginPending) (bool, error) {
	if err := s.faults[mfaFaultConsumePending]; err != nil {
		return false, err
	}
	state := s.writeState(ctx)
	if s.reject[mfaFaultConsumePending] || !reflect.DeepEqual(state.pending[pending.ID], pending) {
		return false, nil
	}
	delete(state.pending, pending.ID)
	return true, nil
}

func (s *mfaFlowStore) SaveMFALoginSetup(ctx context.Context,
	pending goauth.MFALoginPending, setup goauth.MFALoginSetup,
) error {
	if err := s.faults["save_setup"]; err != nil {
		return err
	}
	state := s.writeState(ctx)
	if !reflect.DeepEqual(state.pending[pending.ID], pending) || pending.Kind != goauth.MFALoginKindEnrollment ||
		len(setup.RecoveryDigests) != 10 {
		return goauth.ErrMFALoginDenied
	}
	pending.Setup = mfaFlowCloneSetup(setup)
	state.pending[pending.ID] = pending
	return nil
}

func (s *mfaFlowStore) ReplaceMFAFactor(ctx context.Context, _ goauth.SubjectID,
	previous, next goauth.MFAFactorRecord,
) (bool, error) {
	if err := s.faults[mfaFaultReplaceFactor]; err != nil {
		return false, err
	}
	state := s.writeState(ctx)
	if s.reject[mfaFaultReplaceFactor] || !reflect.DeepEqual(state.factor, previous) ||
		next.ID == "" || next.Revision != previous.Revision+1 {
		return false, nil
	}
	next.Ciphertext = bytes.Clone(next.Ciphertext)
	state.factor = next
	return true, nil
}

func (s *mfaFlowStore) ReplaceMFARecovery(ctx context.Context, _ goauth.SubjectID, digests [][]byte) error {
	if err := s.faults[mfaFaultReplaceRecovery]; err != nil {
		return err
	}
	state := s.writeState(ctx)
	state.recovery = make(map[string]bool, len(digests))
	for _, digest := range digests {
		state.recovery[string(digest)] = true
	}
	return nil
}

func (s *mfaFlowStore) SaveMFAEnrollment(ctx context.Context, enrollment goauth.MFAEnrollmentRecord) error {
	if err := s.faults["save_enrollment"]; err != nil {
		return err
	}
	enrollment.Ciphertext = bytes.Clone(enrollment.Ciphertext)
	s.writeState(ctx).enrollment = enrollment
	return nil
}

func (s *mfaFlowStore) LockMFAEnrollment(ctx context.Context, subject goauth.SubjectID) (goauth.MFAEnrollmentRecord, error) {
	if err := s.faults["lock_enrollment"]; err != nil {
		return goauth.MFAEnrollmentRecord{}, err
	}
	enrollment := s.writeState(ctx).enrollment
	if enrollment.ID == "" || enrollment.SubjectID != subject {
		return goauth.MFAEnrollmentRecord{}, goauth.ErrMFALoginDenied
	}
	enrollment.Ciphertext = bytes.Clone(enrollment.Ciphertext)
	return enrollment, nil
}

func (s *mfaFlowStore) CancelMFAEnrollment(ctx context.Context, subject goauth.SubjectID,
	sessionID string, binding [32]byte,
) error {
	if err := s.faults["cancel_enrollment"]; err != nil {
		return err
	}
	state := s.writeState(ctx)
	if state.enrollment.SubjectID == subject && state.enrollment.SessionID == sessionID && state.enrollment.Binding == binding {
		state.enrollment = goauth.MFAEnrollmentRecord{}
	}
	return nil
}

func (s *mfaFlowStore) InvalidateMFAState(ctx context.Context, subject goauth.SubjectID) error {
	if err := s.faults[mfaFaultInvalidate]; err != nil {
		return err
	}
	state := s.writeState(ctx)
	for id, pending := range state.pending {
		if pending.SubjectID == subject {
			delete(state.pending, id)
		}
	}
	if state.enrollment.SubjectID == subject {
		state.enrollment = goauth.MFAEnrollmentRecord{}
	}
	return nil
}

func (s *mfaFlowStore) CreateSession(ctx context.Context, record goauth.SessionRecord) error {
	if err := s.faults[mfaFaultCreateSession]; err != nil {
		return err
	}
	if err := s.Store.CreateSession(ctx, record); err != nil {
		return err
	}
	state := s.writeState(ctx)
	state.sessions = append(state.sessions, record)
	return nil
}

func (s *mfaFlowStore) RecordSecurityEvent(ctx context.Context, event goauth.SecurityEvent) error {
	if err := s.faults[testAuditStage]; err != nil {
		return err
	}
	if err := s.Store.RecordSecurityEvent(ctx, event); err != nil {
		return err
	}
	state := s.readState(ctx) // Failed password audit is intentionally nontransactional.
	state.audits = append(state.audits, event)
	return nil
}

func (s *mfaFlowStore) MarkMFASessionAdmission(ctx context.Context,
	session goauth.Session, admission goauth.MFASessionAdmission,
) error {
	if err := s.faults["mark_admission"]; err != nil {
		return err
	}
	state := s.writeState(ctx)
	if state.admissions[session.ID] != "" ||
		(admission != goauth.MFASessionAdmissionExternal &&
			(admission != goauth.MFASessionAdmissionFactor || !state.factor.Enabled)) {
		return goauth.ErrMFALoginDenied
	}
	security, err := s.IntrospectSession(ctx, session.ID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(security.Session, session) {
		return goauth.ErrMFALoginDenied
	}
	state.admissions[session.ID] = admission
	return nil
}

func (s *mfaFlowStore) AdmitRequiredMFASession(ctx context.Context, session goauth.Session) error {
	if err := s.faults["admit_session"]; err != nil {
		return err
	}
	state := s.readState(ctx)
	admission := state.admissions[session.ID]
	if admission == goauth.MFASessionAdmissionExternal ||
		(admission == goauth.MFASessionAdmissionFactor && state.factor.Enabled) {
		return nil
	}
	return goauth.ErrMFARequired
}

type mfaFlowHasher struct{}

func (mfaFlowHasher) HashPassword(password string) (string, error) {
	return mfaHashPrefix + password, nil
}

func (mfaFlowHasher) VerifyPassword(phc, password string) error {
	if phc != mfaHashPrefix+password {
		return goauth.ErrInvalidCredentials
	}
	return nil
}

type mfaFlowFixture struct {
	runtime *goauth.Runtime
	store   *mfaFlowStore
	account goauth.Account
	now     time.Time
	binding [32]byte
	request goauth.LoginRequest
	codec   *goauth.MFAFactorCodec
}

func newMFAFlowFixture(t *testing.T, mode goauth.MFAMode, options ...func(*goauth.Config)) *mfaFlowFixture {
	t.Helper()
	f := &mfaFlowFixture{now: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC), binding: [32]byte{41}}
	subject, err := goauth.ParseSubjectID("6e311da7-d8f3-4600-b6a2-ff5c91792c41")
	require.NoError(t, err)
	verified := f.now.Add(-time.Hour)
	f.account = goauth.Account{
		Subject: goauth.Subject{ID: subject, Status: goauth.SubjectStatusActive, SecurityVersion: 1},
		PrimaryEmail: goauth.Identifier{
			ID: "mfa-fixture-email", SubjectID: subject, Scheme: goauth.IdentifierSchemeEmail,
			DisplayValue: mfaFlowEmail, NormalizedValue: mfaFlowEmail, VerifiedAt: &verified,
		},
	}
	keys, err := goauth.NewKeyRing("flow-mfa", goauth.Key{ID: "flow-mfa", Material: bytes.Repeat([]byte{72}, 32)})
	require.NoError(t, err)
	f.codec, err = goauth.NewMFAFactorCodec(keys, "goauth/mfa")
	require.NoError(t, err)
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		base, ok := c.Store.(*testkit.Store)
		require.True(t, ok)
		f.store = &mfaFlowStore{
			Store: base, attemptLimit: 100, commitErr: errMFAFlowCommit,
			faults: make(map[string]error), reject: make(map[string]bool),
			state: mfaFlowState{
				pending: make(map[string]goauth.MFALoginPending), recovery: make(map[string]bool),
				admissions: make(map[string]goauth.MFASessionAdmission),
			},
		}
		c.Store, c.AuthTransaction, c.AuditSink = f.store, f.store, f.store
		c.MFAMode, c.MFAKeys = mode, &keys
		c.PasswordHasher = mfaFlowHasher{}
		c.Now = func() time.Time { return f.now }
		for _, option := range options {
			option(c)
		}
	})
	require.NoError(t, err)
	f.runtime = fixture.Runtime
	_, err = f.store.CreateLocalAccount(t.Context(), goauth.LocalAccountRecord{
		Account: f.account, PasswordPHC: mfaHashPrefix + mfaFlowPassword,
	})
	require.NoError(t, err)
	f.request = goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: mfaFlowEmail},
			Password:   mfaFlowPassword,
		},
		Realm: goauth.RealmUser,
	}
	return f
}

func (f *mfaFlowFixture) begin(t *testing.T) *goauth.MFALoginChallenge {
	t.Helper()
	result, err := f.runtime.BeginLocalLogin(t.Context(), f.request, f.binding)
	require.NoError(t, err)
	require.NotNil(t, result.Pending)
	require.Empty(t, result.Login)
	return result.Pending
}

func (f *mfaFlowFixture) setup(t *testing.T) (*goauth.MFALoginChallenge, goauth.MFAEnrollment) {
	t.Helper()
	pending := f.begin(t)
	setup, err := f.runtime.BeginLocalLoginEnrollment(t.Context(), pending.ID, f.binding)
	require.NoError(t, err)
	return pending, setup
}

func (f *mfaFlowFixture) enableFactor(t *testing.T) {
	t.Helper()
	factor := goauth.MFAFactorRecord{ID: mfaFlowID(2), Revision: 1, Enabled: true, LastStep: -1}
	var err error
	factor.KeyID, factor.Ciphertext, err = f.codec.Seal(f.account.Subject.ID, factor.ID, mfaFlowSecret)
	require.NoError(t, err)
	f.store.state.factor = factor
}

func mfaFlowID(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func mfaFlowCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, now)
	require.NoError(t, err)
	return code
}

var (
	_ goauth.RuntimeStore     = (*mfaFlowStore)(nil)
	_ goauth.MFARequiredStore = (*mfaFlowStore)(nil)
	_ goauth.AuthTransaction  = (*mfaFlowStore)(nil)
	_ goauth.AuditSink        = (*mfaFlowStore)(nil)
)
