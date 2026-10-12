package goauth_test

import (
	"bytes"
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestMFARuntimeRequiredLoginPublishesOnlyPending(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeRequired)
	legacy, err := f.runtime.Login(t.Context(), f.request)
	require.ErrorIs(t, err, goauth.ErrMFARequired)
	require.Empty(t, legacy)

	request := f.request
	request.Credential.Password = "incorrect-password"
	invalid, err := f.runtime.BeginLocalLogin(t.Context(), request, f.binding)
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	require.Empty(t, invalid)
	require.Empty(t, f.store.state.pending)
	require.Empty(t, f.store.state.factor)

	pending := f.begin(t)
	require.Equal(t, goauth.MFALoginKindEnrollment, pending.Kind)
	require.Equal(t, f.now.Add(goauth.MFALoginLifetime), pending.ExpiresAt)
	record := f.store.state.pending[pending.ID]
	require.Equal(t, f.account.Subject.ID, record.SubjectID)
	require.Equal(t, f.binding, record.BindingDigest)
	require.Equal(t, f.now, record.AuthenticatedAt)
	require.Equal(t, f.account.Subject.SecurityVersion, record.SecurityVersion)
	require.Equal(t, f.store.state.factor.ID, record.FactorID)
	require.Equal(t, f.store.state.factor.Revision, record.FactorRevision)
	require.False(t, f.store.state.factor.Enabled)
	require.Empty(t, f.store.state.sessions)
	require.Empty(t, f.store.state.admissions)

	// A pending selector is neither an access token nor a refresh token.
	_, err = f.runtime.AuthenticateSession(t.Context(), pending.ID)
	require.Error(t, err)
	_, err = f.runtime.Refresh(t.Context(), pending.ID)
	require.ErrorIs(t, err, goauth.ErrInvalidToken)
}

func TestMFARuntimeBeginLoginFailsClosed(t *testing.T) {
	for _, scenario := range []string{"empty binding", "factor error", "pending error", "commit error", "expiry after commit"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			binding := f.binding
			want := goauth.ErrMFALoginDenied
			switch scenario {
			case "empty binding":
				binding = [32]byte{}
			case "factor error":
				f.store.faults["ensure_factor"] = errMFAFlowCommit
				want = errMFAFlowCommit
			case "pending error":
				f.store.faults["create_pending"] = errMFAFlowCommit
				want = errMFAFlowCommit
			case "commit error":
				f.store.failCommitAt = 1
				want = errMFAFlowCommit
			case "expiry after commit":
				f.store.afterOwnedCommit = func(int) { f.now = f.now.Add(goauth.MFALoginLifetime) }
			}
			result, err := f.runtime.BeginLocalLogin(t.Context(), f.request, binding)
			require.ErrorIs(t, err, want)
			require.Empty(t, result)
			require.Empty(t, f.store.state.sessions)
			require.Empty(t, f.store.state.admissions)
			if scenario != "expiry after commit" {
				require.Empty(t, f.store.state.pending)
				require.Empty(t, f.store.state.factor)
			}
		})
	}
}

func TestMFARuntimeNewPasswordContinuationReplacesPriorRealmFlow(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeRequired)
	first, setup := f.setup(t)
	latest := f.begin(t)
	require.Len(t, f.store.state.pending, 1)
	require.NotContains(t, f.store.state.pending, first.ID)
	require.Contains(t, f.store.state.pending, latest.ID)
	result, err := f.runtime.CompleteLocalLoginEnrollment(
		t.Context(), first.ID, setup.ID, f.binding, mfaFlowCode(t, setup.Secret, f.now),
	)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, result)
	require.Empty(t, f.store.state.sessions)
	require.False(t, f.store.state.factor.Enabled)
}

func TestMFARuntimeEnrollmentSetupIsEncryptedBoundAndReplaceable(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeRequired)
	pending, first := f.setup(t)
	require.Len(t, first.RecoveryCodes, 10)
	require.NotEmpty(t, first.Secret)
	require.Contains(t, first.URL, "otpauth://totp/")
	require.Equal(t, pending.ExpiresAt, first.ExpiresAt)
	stored := f.store.state.pending[pending.ID].Setup
	require.Equal(t, first.ID, stored.ID)
	require.NotEmpty(t, stored.Ciphertext)
	require.NotContains(t, string(stored.Ciphertext), first.Secret)
	plain, err := f.codec.Open(f.account.Subject.ID, stored.ID, stored.KeyID, stored.Ciphertext)
	require.NoError(t, err)
	require.Equal(t, first.Secret, string(plain))
	clear(plain)
	unique := make(map[string]bool)
	for i, code := range first.RecoveryCodes {
		require.True(t, goauth.IsMFARecoveryCode(code))
		require.False(t, unique[code])
		unique[code] = true
		digest, digestErr := f.codec.RecoveryDigest(f.account.Subject.ID, first.ID, code)
		require.NoError(t, digestErr)
		require.Equal(t, digest, stored.RecoveryDigests[i])
	}
	require.Empty(t, f.store.state.recovery)
	require.Empty(t, f.store.state.sessions)
	require.False(t, f.store.state.factor.Enabled)

	f.now = f.now.Add(30 * time.Second)
	second, err := f.runtime.BeginLocalLoginEnrollment(t.Context(), pending.ID, f.binding)
	require.NoError(t, err)
	require.NotEqual(t, first.ID, second.ID)
	require.Equal(t, first.ExpiresAt, second.ExpiresAt)
	denied, err := f.runtime.CompleteLocalLoginEnrollment(
		t.Context(), pending.ID, first.ID, f.binding, mfaFlowCode(t, first.Secret, f.now),
	)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, denied)
	require.Equal(t, second.ID, f.store.state.pending[pending.ID].Setup.ID)
	result, err := f.runtime.CompleteLocalLoginEnrollment(
		t.Context(), pending.ID, second.ID, f.binding, mfaFlowCode(t, second.Secret, f.now),
	)
	require.NoError(t, err)
	require.NotEmpty(t, result.Tokens.AccessToken)
}

func TestMFARuntimeRequiredEnrollmentCommitsAuthorityAtomically(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeRequired)
	pending, setup := f.setup(t)
	f.request.Realm = goauth.RealmAdmin
	sibling := f.begin(t)
	f.request.Realm = goauth.RealmUser
	require.NotEqual(t, pending.ID, sibling.ID)
	code := mfaFlowCode(t, setup.Secret, f.now)
	result, err := f.runtime.CompleteLocalLoginEnrollment(t.Context(), pending.ID, setup.ID, f.binding, code)
	require.NoError(t, err)
	require.Equal(t, f.account.Subject.ID, result.Account.Subject.ID)
	require.EqualValues(t, 2, result.Account.Subject.SecurityVersion)
	require.EqualValues(t, 2, result.Tokens.Session.SecurityVersion)
	require.Equal(t, goauth.SessionScopeAuthenticated, result.Tokens.Session.Scope)
	require.NotEmpty(t, result.Tokens.AccessToken)
	require.NotEmpty(t, result.Tokens.RefreshToken)
	require.True(t, f.store.state.factor.Enabled)
	require.Equal(t, setup.ID, f.store.state.factor.ID)
	require.EqualValues(t, 2, f.store.state.factor.Revision)
	require.Equal(t, f.now.Unix()/30, f.store.state.factor.LastStep)
	require.Len(t, f.store.state.sessions, 1)
	require.Len(t, f.store.state.recovery, 10)
	require.Empty(t, f.store.state.pending)
	require.Equal(t, goauth.MFASessionAdmissionFactor, f.store.state.admissions[result.Tokens.Session.ID])
	account, err := f.store.GetAccount(t.Context(), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, result.Account.Subject.SecurityVersion, account.Subject.SecurityVersion)
	auth, err := f.runtime.AuthenticateSession(t.Context(), result.Tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, result.Tokens.Session.ID, auth.SessionID)
	mfaFlowRequireAudit(t, f, "mfa.enrolled")
	mfaFlowRequireAudit(t, f, "mfa.login")

	replay, err := f.runtime.CompleteLocalLoginEnrollment(t.Context(), pending.ID, setup.ID, f.binding, code)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, replay)
	require.Len(t, f.store.state.sessions, 1)

	// The code that activated the factor cannot also authorize the next login.
	next := f.begin(t)
	require.Equal(t, goauth.MFALoginKindFactor, next.Kind)
	replay, err = f.runtime.CompleteLocalLogin(t.Context(), next.ID, f.binding, code)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, replay)
	require.Contains(t, f.store.state.pending, next.ID)
	result, err = f.runtime.CompleteLocalLogin(t.Context(), next.ID, f.binding, setup.RecoveryCodes[0])
	require.NoError(t, err)
	require.NotEmpty(t, result.Tokens.AccessToken)
	require.Len(t, f.store.state.recovery, 9)
}

func TestMFARuntimeEnrollmentRejectsInvalidContinuation(t *testing.T) {
	for _, scenario := range []string{"binding", "expired", "factor revision", "security version", "factor purpose"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			pending := f.begin(t)
			binding := f.binding
			switch scenario {
			case "binding":
				binding[0]++
			case "expired":
				f.now = pending.ExpiresAt
			case "factor revision":
				f.store.state.factor.Revision++
			case "security version":
				_, err := f.runtime.LogoutAll(t.Context(), f.account.Subject.ID)
				require.NoError(t, err)
			case "factor purpose":
				record := f.store.state.pending[pending.ID]
				record.Kind = goauth.MFALoginKindFactor
				f.store.state.pending[pending.ID] = record
			}
			setup, err := f.runtime.BeginLocalLoginEnrollment(t.Context(), pending.ID, binding)
			require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
			require.Empty(t, setup)
			require.Empty(t, f.store.state.pending[pending.ID].Setup)
			require.Zero(t, f.store.state.attempts)
			require.Empty(t, f.store.state.sessions)
		})
	}
}

func TestMFARuntimeEnrollmentDenialsCommitOnlyAttemptBudget(t *testing.T) {
	for _, limited := range []bool{false, true} {
		name := "incorrect code"
		if limited {
			name = "rate limited"
		}
		t.Run(name, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			pending, setup := f.setup(t)
			before := f.store.state.clone()
			want := goauth.ErrMFALoginDenied
			if limited {
				f.store.attemptLimit = before.attempts
				want = goauth.ErrAuthenticationRateLimited
			}
			result, err := f.runtime.CompleteLocalLoginEnrollment(t.Context(), pending.ID, setup.ID, f.binding, "invalid")
			require.ErrorIs(t, err, want)
			require.Empty(t, result)
			if !limited {
				before.attempts++
			}
			require.Equal(t, before, f.store.state)
			account, err := f.store.GetAccount(t.Context(), f.account.Subject.ID)
			require.NoError(t, err)
			require.EqualValues(t, 1, account.Subject.SecurityVersion)
		})
	}
}

func TestMFARuntimeEnrollmentRollsBackEveryAuthorityWrite(t *testing.T) {
	for _, operation := range []string{
		"replace_factor", "replace_recovery", "consume_pending", "invalidate",
		"create_session", "mark_admission", "audit", "commit",
	} {
		t.Run(operation, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			pending, setup := f.setup(t)
			before := f.store.state.clone()
			if operation == "commit" {
				f.store.failCommitAt = f.store.owned + 2
			} else {
				f.store.faults[operation] = errMFAFlowCommit
			}
			result, err := f.runtime.CompleteLocalLoginEnrollment(
				t.Context(), pending.ID, setup.ID, f.binding, mfaFlowCode(t, setup.Secret, f.now),
			)
			require.ErrorIs(t, err, errMFAFlowCommit)
			require.Empty(t, result)
			require.Equal(t, before, f.store.state)
			account, err := f.store.GetAccount(t.Context(), f.account.Subject.ID)
			require.NoError(t, err)
			require.EqualValues(t, 1, account.Subject.SecurityVersion)
			delete(f.store.faults, operation)
			f.store.failCommitAt = 0
			result, err = f.runtime.CompleteLocalLoginEnrollment(
				t.Context(), pending.ID, setup.ID, f.binding, mfaFlowCode(t, setup.Secret, f.now),
			)
			require.NoError(t, err)
			require.NotEmpty(t, result.Tokens.AccessToken)
		})
	}
}

func TestMFARuntimeEnrollmentWithholdsSecretsOnUncertainCommit(t *testing.T) {
	for _, phase := range []string{"begin setup", "confirm setup"} {
		t.Run(phase, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			pending := f.begin(t)
			f.store.commitErr = goauth.ErrOperationOutcomeUnknown
			if phase == "begin setup" {
				f.store.unknownCommitAt = f.store.owned + 1
				setup, err := f.runtime.BeginLocalLoginEnrollment(t.Context(), pending.ID, f.binding)
				require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
				require.Empty(t, setup)
				require.NotEmpty(t, f.store.state.pending[pending.ID].Setup.ID)
				require.Empty(t, f.store.state.sessions)
				return
			}
			setup, err := f.runtime.BeginLocalLoginEnrollment(t.Context(), pending.ID, f.binding)
			require.NoError(t, err)
			f.store.unknownCommitAt = f.store.owned + 2
			result, err := f.runtime.CompleteLocalLoginEnrollment(
				t.Context(), pending.ID, setup.ID, f.binding, mfaFlowCode(t, setup.Secret, f.now),
			)
			require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
			require.Empty(t, result)
			require.True(t, f.store.state.factor.Enabled)
			require.Empty(t, f.store.state.pending)
			require.Len(t, f.store.state.sessions, 1)
		})
	}
}

func TestMFARuntimeEnrollmentRechecksAfterTokenPreparation(t *testing.T) {
	for _, scenario := range []string{"binding", "setup replacement", "expiry", "factor CAS", "pending CAS"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			pending, setup := f.setup(t)
			finalTransaction := f.store.owned + 2
			f.store.beforeOwned = func(sequence int) {
				if sequence != finalTransaction {
					return
				}
				record := f.store.state.pending[pending.ID]
				switch scenario {
				case "binding":
					record.BindingDigest[0]++
				case "setup replacement":
					record.Setup.ID = mfaFlowID(7)
				case "expiry":
					f.now = pending.ExpiresAt
				case "factor CAS":
					f.store.reject["replace_factor"] = true
				case "pending CAS":
					f.store.reject["consume_pending"] = true
				}
				f.store.state.pending[pending.ID] = record
			}
			result, err := f.runtime.CompleteLocalLoginEnrollment(
				t.Context(), pending.ID, setup.ID, f.binding, mfaFlowCode(t, setup.Secret, f.now),
			)
			require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
			require.Empty(t, result)
			require.False(t, f.store.state.factor.Enabled)
			require.Empty(t, f.store.state.sessions)
			require.Empty(t, f.store.state.recovery)
			require.Equal(t, 1, f.store.state.attempts)
		})
	}
}

func TestMFARuntimeExpiredCommitDoesNotPublishPreparedTokens(t *testing.T) {
	for _, enrollment := range []bool{false, true} {
		name := "factor"
		if enrollment {
			name = "enrollment"
		}
		t.Run(name, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			var pending *goauth.MFALoginChallenge
			var setup goauth.MFAEnrollment
			secret := mfaFlowSecret
			if enrollment {
				pending, setup = f.setup(t)
				secret = setup.Secret
			} else {
				f.enableFactor(t)
				pending = f.begin(t)
			}
			finalTransaction := f.store.owned + 2
			f.store.afterOwnedCommit = func(sequence int) {
				if sequence == finalTransaction {
					f.now = pending.ExpiresAt
				}
			}
			code := mfaFlowCode(t, secret, f.now)
			var result goauth.LoginResult
			var err error
			if enrollment {
				result, err = f.runtime.CompleteLocalLoginEnrollment(t.Context(), pending.ID, setup.ID, f.binding, code)
			} else {
				result, err = f.runtime.CompleteLocalLogin(t.Context(), pending.ID, f.binding, code)
			}
			require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
			require.Empty(t, result)
			require.Empty(t, f.store.state.pending)
			require.Len(t, f.store.state.sessions, 1)
		})
	}
}

func TestMFARuntimeOptionalLoginAndFactorCompletion(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	unenrolled, err := f.runtime.BeginLocalLogin(t.Context(), f.request, [32]byte{})
	require.NoError(t, err)
	require.Nil(t, unenrolled.Pending)
	require.NotEmpty(t, unenrolled.Login.Tokens.AccessToken)
	f.enableFactor(t)
	pending := f.begin(t)
	require.Equal(t, goauth.MFALoginKindFactor, pending.Kind)
	result, err := f.runtime.CompleteLocalLogin(t.Context(), pending.ID, f.binding, mfaFlowCode(t, mfaFlowSecret, f.now))
	require.NoError(t, err)
	require.EqualValues(t, 1, result.Account.Subject.SecurityVersion)
	require.NotEmpty(t, result.Tokens.AccessToken)
	require.Empty(t, f.store.state.pending)
	require.Equal(t, f.now.Unix()/30, f.store.state.factor.LastStep)
	require.Equal(t, goauth.MFASessionAdmissionFactor, f.store.state.admissions[result.Tokens.Session.ID])
	_, err = f.runtime.AuthenticateSession(t.Context(), result.Tokens.AccessToken)
	require.NoError(t, err)
	mfaFlowRequireAudit(t, f, "mfa.login")
	result, err = f.runtime.CompleteLocalLogin(t.Context(), pending.ID, f.binding, mfaFlowCode(t, mfaFlowSecret, f.now))
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, result)
}

func TestMFARuntimeFactorDenialsAndRollback(t *testing.T) {
	for _, scenario := range []string{
		"wrong code", "rate limited", "wrong binding", "expired", "consume CAS", "session error", "audit error", "commit error",
	} {
		t.Run(scenario, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			f.enableFactor(t)
			pending := f.begin(t)
			before := f.store.state.clone()
			code := mfaFlowCode(t, mfaFlowSecret, f.now)
			binding := f.binding
			want := goauth.ErrMFALoginDenied
			durableAttempt := false
			switch scenario {
			case "wrong code":
				code, durableAttempt = "invalid", true
			case "rate limited":
				f.store.attemptLimit = 0
				want = goauth.ErrAuthenticationRateLimited
			case "wrong binding":
				binding[0]++
			case "expired":
				f.now = pending.ExpiresAt
			case "consume CAS":
				f.store.reject["consume_pending"] = true
			case "session error":
				f.store.faults["create_session"], want = errMFAFlowCommit, errMFAFlowCommit
			case "audit error":
				f.store.faults["audit"], want = errMFAFlowCommit, errMFAFlowCommit
			case "commit error":
				f.store.failCommitAt, want = f.store.owned+2, errMFAFlowCommit
			}
			result, err := f.runtime.CompleteLocalLogin(t.Context(), pending.ID, binding, code)
			require.ErrorIs(t, err, want)
			require.Empty(t, result)
			if durableAttempt {
				before.attempts++
			}
			require.Equal(t, before, f.store.state)
		})
	}
}

func TestMFARuntimeRequiredAdmissionIsCheckedLive(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeRequired)
	f.enableFactor(t)
	pending := f.begin(t)
	result, err := f.runtime.CompleteLocalLogin(t.Context(), pending.ID, f.binding, mfaFlowCode(t, mfaFlowSecret, f.now))
	require.NoError(t, err)
	_, err = f.runtime.AuthenticateSession(t.Context(), result.Tokens.AccessToken)
	require.NoError(t, err)
	f.store.state.factor.Enabled = false
	_, err = f.runtime.AuthenticateSession(t.Context(), result.Tokens.AccessToken)
	require.ErrorIs(t, err, goauth.ErrMFARequired)
	f.store.state.factor.Enabled = true
	delete(f.store.state.admissions, result.Tokens.Session.ID)
	_, err = f.runtime.AuthenticateSession(t.Context(), result.Tokens.AccessToken)
	require.ErrorIs(t, err, goauth.ErrMFARequired)
}

func TestMFARuntimeEnrollmentInputAndAvailabilityGuards(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	_, err := f.runtime.BeginLocalLoginEnrollment(t.Context(), mfaFlowID(1), f.binding)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	_, err = f.runtime.CompleteLocalLoginEnrollment(t.Context(), mfaFlowID(1), mfaFlowID(2), f.binding, "123456")
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	f = newMFAFlowFixture(t, goauth.MFAModeRequired)
	_, err = f.runtime.BeginLocalLoginEnrollment(t.Context(), "invalid", f.binding)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	_, err = f.runtime.CompleteLocalLoginEnrollment(t.Context(), "invalid", "invalid", f.binding, "123456")
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	_, err = f.runtime.CompleteLocalLogin(t.Context(), mfaFlowID(1), f.binding, strings.Repeat("1", 129))
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	_, err = f.runtime.CompleteLocalLoginEnrollment(
		t.Context(), mfaFlowID(1), mfaFlowID(2), f.binding, strings.Repeat("1", 129),
	)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	withoutKeys := newMFAFlowFixture(t, goauth.MFAModeOptional, func(c *goauth.Config) { c.MFAKeys = nil })
	withoutKeys.enableFactor(t)
	result, err := withoutKeys.runtime.BeginLocalLogin(t.Context(), withoutKeys.request, withoutKeys.binding)
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
	require.Empty(t, result)
	_, err = withoutKeys.runtime.CompleteLocalLogin(t.Context(), mfaFlowID(1), withoutKeys.binding, "123456")
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
}

func TestMFARuntimeEnrollmentRejectsCorruptSetupAndVersionOverflow(t *testing.T) {
	for _, scenario := range []string{"digest count", "ciphertext", "key unavailable", "version overflow"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			pending, setup := f.setup(t)
			record := f.store.state.pending[pending.ID]
			want := goauth.ErrMFAUnavailable
			switch scenario {
			case "digest count":
				record.Setup.RecoveryDigests = record.Setup.RecoveryDigests[:9]
				want = goauth.ErrMFALoginDenied
			case "ciphertext":
				record.Setup.Ciphertext = bytes.Repeat([]byte{5}, 48)
			case "key unavailable":
				record.Setup.KeyID = "removed-key"
			case "version overflow":
				// A store decorator supplies an exhausted canonical version without
				// executing billions of account invalidations in the fixture.
				f = mfaFlowOverflowFixture(t)
				pending, setup = f.setup(t)
				record = f.store.state.pending[pending.ID]
			}
			f.store.state.pending[pending.ID] = record
			before := f.store.state.clone()
			result, err := f.runtime.CompleteLocalLoginEnrollment(
				t.Context(), pending.ID, setup.ID, f.binding, mfaFlowCode(t, setup.Secret, f.now),
			)
			require.ErrorIs(t, err, want)
			require.Empty(t, result)
			require.Equal(t, before, f.store.state)
		})
	}
}

type mfaFlowOverflowStore struct{ *mfaFlowStore }

func (s *mfaFlowOverflowStore) FindLocalAccount(ctx context.Context,
	identifier goauth.IdentifierInput,
) (goauth.LocalAccountRecord, error) {
	record, err := s.mfaFlowStore.FindLocalAccount(ctx, identifier)
	record.Account.Subject.SecurityVersion = math.MaxInt64
	return record, err
}

func (s *mfaFlowOverflowStore) LockAccount(ctx context.Context, subject goauth.SubjectID) (goauth.Account, error) {
	account, err := s.mfaFlowStore.LockAccount(ctx, subject)
	account.Subject.SecurityVersion = math.MaxInt64
	return account, err
}

func mfaFlowOverflowFixture(t *testing.T) *mfaFlowFixture {
	t.Helper()
	return newMFAFlowFixture(t, goauth.MFAModeRequired, func(c *goauth.Config) {
		store, ok := c.Store.(*mfaFlowStore)
		require.True(t, ok)
		c.Store = &mfaFlowOverflowStore{mfaFlowStore: store}
	})
}

func mfaFlowRequireAudit(t *testing.T, f *mfaFlowFixture, eventType string) {
	t.Helper()
	for _, event := range f.store.state.audits {
		if string(event.Type) == eventType {
			require.Equal(t, f.account.Subject.ID, event.SubjectID)
			return
		}
	}
	require.Fail(t, "missing audit event", eventType)
}

func TestMFARuntimeSetupErrorsDoNotPublishEnrollment(t *testing.T) {
	for _, scenario := range []string{"attempt error", "save error", "commit error", "rate limited"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			pending := f.begin(t)
			before := f.store.state.clone()
			want := errMFAFlowCommit
			switch scenario {
			case "attempt error":
				f.store.faults["take_attempt"] = want
			case "save error":
				f.store.faults["save_setup"] = want
			case "commit error":
				f.store.failCommitAt = f.store.owned + 1
			case "rate limited":
				f.store.attemptLimit = 0
				want = goauth.ErrAuthenticationRateLimited
			}
			setup, err := f.runtime.BeginLocalLoginEnrollment(t.Context(), pending.ID, f.binding)
			require.ErrorIs(t, err, want)
			require.Empty(t, setup)
			require.Equal(t, before, f.store.state)
		})
	}
}

func TestMFARuntimeFactorPreservesStoreReadErrors(t *testing.T) {
	fault := errors.New("MFA read unavailable")
	for _, operation := range []string{"find_pending", "lock_factor", "lock_pending"} {
		t.Run(operation, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeRequired)
			f.enableFactor(t)
			pending := f.begin(t)
			f.store.faults[operation] = fault
			result, err := f.runtime.CompleteLocalLogin(t.Context(), pending.ID, f.binding, mfaFlowCode(t, mfaFlowSecret, f.now))
			require.ErrorIs(t, err, fault)
			require.Empty(t, result)
			require.Zero(t, f.store.state.attempts)
			require.Empty(t, f.store.state.sessions)
		})
	}
}
