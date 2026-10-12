package goauth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func mfaOptionalSession(t *testing.T, f *mfaFlowFixture) (goauth.AuthContext, goauth.TokenPair) {
	t.Helper()
	result, err := f.runtime.BeginLocalLogin(t.Context(), f.request, f.binding)
	require.NoError(t, err)
	require.Nil(t, result.Pending)
	require.NotEmpty(t, result.Login.Tokens.AccessToken)
	auth, err := f.runtime.AuthenticateSession(t.Context(), result.Login.Tokens.AccessToken)
	require.NoError(t, err)
	return auth, result.Login.Tokens
}

func mfaOptionalEnrollment(t *testing.T, f *mfaFlowFixture, auth goauth.AuthContext) goauth.MFAEnrollment {
	t.Helper()
	enrollment, err := f.runtime.BeginMFAEnrollment(t.Context(), goauth.MFAEnrollmentRequest{
		Auth: auth, Password: mfaFlowPassword, Binding: f.binding,
	})
	require.NoError(t, err)
	require.NotEmpty(t, enrollment.Secret)
	return enrollment
}

func mfaOptionalConfirmation(
	t *testing.T, f *mfaFlowFixture, auth goauth.AuthContext, enrollment goauth.MFAEnrollment,
) goauth.MFAEnrollmentConfirmRequest {
	t.Helper()
	return goauth.MFAEnrollmentConfirmRequest{
		Auth: auth, Password: mfaFlowPassword, EnrollmentID: enrollment.ID, Binding: f.binding,
		Code: mfaFlowCode(t, enrollment.Secret, f.now),
	}
}

func mfaOptionalRecoveryDigests(t *testing.T, f *mfaFlowFixture, codes []string) {
	t.Helper()
	require.Len(t, codes, 10)
	require.Len(t, f.store.state.recovery, 10)
	seen := make(map[string]bool, len(codes))
	for _, code := range codes {
		require.True(t, goauth.IsMFARecoveryCode(code))
		require.False(t, seen[code], "recovery codes must be distinct")
		seen[code] = true
		digest, err := f.codec.RecoveryDigest(f.account.Subject.ID, f.store.state.factor.ID, code)
		require.NoError(t, err)
		require.True(t, f.store.state.recovery[string(digest)])
		require.NotContains(t, f.store.state.recovery, code, "only digests are persisted")
	}
}

func mfaOptionalInvalidated(t *testing.T, f *mfaFlowFixture, tokens goauth.TokenPair, action string) {
	t.Helper()
	account, err := f.store.GetAccount(t.Context(), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, tokens.Session.SecurityVersion+1, account.Subject.SecurityVersion)
	security, err := f.store.IntrospectSession(t.Context(), tokens.Session.ID)
	require.NoError(t, err)
	require.NotNil(t, security.Session.RevokedAt)
	auth, err := f.runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	require.Empty(t, auth)
	require.Empty(t, f.store.state.pending)
	require.Empty(t, f.store.state.enrollment)
	require.NotEmpty(t, f.store.state.audits)
	last := f.store.state.audits[len(f.store.state.audits)-1]
	require.Equal(t, goauth.SecurityEventType(action), last.Type)
	require.Equal(t, f.account.Subject.ID, last.SubjectID)
}

func TestMFAOptionalEnrollmentLifecycle(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, tokens := mfaOptionalSession(t, f)
	_, otherTokens := mfaOptionalSession(t, f)
	enrollment := mfaOptionalEnrollment(t, f, auth)
	require.False(t, f.store.state.factor.Enabled)
	require.Empty(t, enrollment.RecoveryCodes)
	require.Equal(t, f.now.Add(5*time.Minute), enrollment.ExpiresAt)
	require.Equal(t, enrollment.ID, f.store.state.enrollment.ID)
	require.Equal(t, auth.SessionID, f.store.state.enrollment.SessionID)
	require.Equal(t, f.binding, f.store.state.enrollment.Binding)
	require.Contains(t, enrollment.URL, "otpauth://totp/")
	plain, err := f.codec.Open(f.account.Subject.ID, enrollment.ID,
		f.store.state.enrollment.KeyID, f.store.state.enrollment.Ciphertext)
	require.NoError(t, err)
	require.Equal(t, enrollment.Secret, string(plain))
	clear(plain)

	request := mfaOptionalConfirmation(t, f, auth, enrollment)
	codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), request)
	require.NoError(t, err)
	require.True(t, f.store.state.factor.Enabled)
	require.Equal(t, enrollment.ID, f.store.state.factor.ID)
	require.Equal(t, int64(2), f.store.state.factor.Revision)
	require.Equal(t, f.now.Unix()/30, f.store.state.factor.LastStep)
	mfaOptionalRecoveryDigests(t, f, codes)
	mfaOptionalInvalidated(t, f, tokens, "mfa.enrolled")
	_, err = f.runtime.AuthenticateSession(t.Context(), otherTokens.AccessToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)

	replayed, err := f.runtime.ConfirmMFAEnrollment(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, replayed)
	pending := f.begin(t)
	require.Equal(t, goauth.MFALoginKindFactor, pending.Kind)
	login, err := f.runtime.CompleteLocalLogin(t.Context(), pending.ID, f.binding, codes[0])
	require.NoError(t, err)
	_, err = f.runtime.AuthenticateSession(t.Context(), login.Tokens.AccessToken)
	require.NoError(t, err)
	require.Len(t, f.store.state.recovery, 9)
}

func TestMFAOptionalEnrollmentRequiresReauthentication(t *testing.T) {
	for _, test := range []struct {
		name    string
		change  func(*goauth.MFAEnrollmentRequest)
		wantErr error
	}{
		{"missing binding", func(r *goauth.MFAEnrollmentRequest) { r.Binding = [32]byte{} }, goauth.ErrMFALoginDenied},
		{"oversized current code", func(r *goauth.MFAEnrollmentRequest) {
			r.CurrentCode = strings.Repeat("1", 129)
		}, goauth.ErrMFALoginDenied},
		{mfaCaseWrongPassword, func(r *goauth.MFAEnrollmentRequest) { r.Password = "incorrect" }, goauth.ErrCurrentPasswordInvalid},
		{"missing subject", func(r *goauth.MFAEnrollmentRequest) { r.Auth.SubjectID = goauth.NilSubjectID }, goauth.ErrMFALoginDenied},
		{"missing session", func(r *goauth.MFAEnrollmentRequest) { r.Auth.SessionID = "" }, goauth.ErrMFALoginDenied},
		{"confirmation scope", func(r *goauth.MFAEnrollmentRequest) {
			r.Auth.Scope = goauth.SessionScopeConfirmation
		}, goauth.ErrMFALoginDenied},
		{"stale version", func(r *goauth.MFAEnrollmentRequest) { r.Auth.SecurityVersion++ }, goauth.ErrMFALoginDenied},
		{"wrong realm", func(r *goauth.MFAEnrollmentRequest) { r.Auth.Realm = goauth.RealmAdmin }, goauth.ErrMFALoginDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeOptional)
			auth, _ := mfaOptionalSession(t, f)
			request := goauth.MFAEnrollmentRequest{Auth: auth, Password: mfaFlowPassword, Binding: f.binding}
			test.change(&request)
			before := f.store.state.clone()
			enrollment, err := f.runtime.BeginMFAEnrollment(t.Context(), request)
			require.ErrorIs(t, err, test.wantErr)
			require.Empty(t, enrollment)
			require.Equal(t, before, f.store.state)
		})
	}
}

func TestMFAOptionalEnrollmentStorageFailuresWithholdSecret(t *testing.T) {
	for _, fault := range []string{"ensure_factor", mfaFaultLockFactor, "take_attempt", "save_enrollment"} {
		t.Run(fault, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeOptional)
			auth, _ := mfaOptionalSession(t, f)
			f.store.faults[fault] = errMFAFlowCommit
			before := f.store.state.clone()
			enrollment, err := f.runtime.BeginMFAEnrollment(t.Context(), goauth.MFAEnrollmentRequest{
				Auth: auth, Password: mfaFlowPassword, Binding: f.binding,
			})
			require.ErrorIs(t, err, errMFAFlowCommit)
			require.Empty(t, enrollment)
			require.Equal(t, before, f.store.state)
		})
	}
}

func TestMFAOptionalManagementUnavailableWithoutKeys(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional, func(c *goauth.Config) { c.MFAKeys = nil })
	auth, _ := mfaOptionalSession(t, f)
	before := f.store.state.clone()
	enrollment, err := f.runtime.BeginMFAEnrollment(t.Context(), goauth.MFAEnrollmentRequest{
		Auth: auth, Password: mfaFlowPassword, Binding: f.binding,
	})
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
	require.Empty(t, enrollment)
	codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), goauth.MFAEnrollmentConfirmRequest{
		Auth: auth, Password: mfaFlowPassword, EnrollmentID: mfaFlowID(15), Binding: f.binding, Code: "123456",
	})
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
	require.Empty(t, codes)
	request := goauth.MFAChangeRequest{Auth: auth, Password: mfaFlowPassword, Code: "123456"}
	codes, err = f.runtime.RegenerateMFARecovery(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
	require.Empty(t, codes)
	require.ErrorIs(t, f.runtime.DisableMFA(t.Context(), request), goauth.ErrMFAUnavailable)
	require.Equal(t, before, f.store.state)
}

func TestMFAOptionalEnrollmentAttemptLimitCommitsDenial(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, _ := mfaOptionalSession(t, f)
	f.store.attemptLimit = 0
	enrollment, err := f.runtime.BeginMFAEnrollment(t.Context(), goauth.MFAEnrollmentRequest{
		Auth: auth, Password: mfaFlowPassword, Binding: f.binding,
	})
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, enrollment)
	require.Zero(t, f.store.state.attempts, "an exhausted budget is not incremented again")
	require.Empty(t, f.store.state.enrollment)
	require.False(t, f.store.state.factor.Enabled)
}

func TestMFAOptionalConfirmationChecksEnrollmentBindings(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*goauth.MFAEnrollmentConfirmRequest, *goauth.MFAEnrollmentRecord)
	}{
		{"malformed selector", func(r *goauth.MFAEnrollmentConfirmRequest, _ *goauth.MFAEnrollmentRecord) {
			r.EnrollmentID = "bad-selector"
		}},
		{"wrong selector", func(r *goauth.MFAEnrollmentConfirmRequest, _ *goauth.MFAEnrollmentRecord) {
			r.EnrollmentID = mfaFlowID(99)
		}},
		{"oversized code", func(r *goauth.MFAEnrollmentConfirmRequest, _ *goauth.MFAEnrollmentRecord) {
			r.Code = strings.Repeat("1", 129)
		}},
		{mfaCaseEmptyBinding, func(r *goauth.MFAEnrollmentConfirmRequest, _ *goauth.MFAEnrollmentRecord) {
			r.Binding = [32]byte{}
		}},
		{"different browser", func(r *goauth.MFAEnrollmentConfirmRequest, _ *goauth.MFAEnrollmentRecord) {
			r.Binding[0]++
		}},
		{"different subject", func(_ *goauth.MFAEnrollmentConfirmRequest, e *goauth.MFAEnrollmentRecord) {
			e.SubjectID = goauth.NewSubjectID()
		}},
		{"different session", func(_ *goauth.MFAEnrollmentConfirmRequest, e *goauth.MFAEnrollmentRecord) {
			e.SessionID += "-other"
		}},
		{"stale factor revision", func(_ *goauth.MFAEnrollmentConfirmRequest, e *goauth.MFAEnrollmentRecord) {
			e.Revision++
		}},
		{"stale security version", func(_ *goauth.MFAEnrollmentConfirmRequest, e *goauth.MFAEnrollmentRecord) {
			e.SecurityVersion++
		}},
		{"not yet valid", func(_ *goauth.MFAEnrollmentConfirmRequest, e *goauth.MFAEnrollmentRecord) {
			e.CreatedAt = e.CreatedAt.Add(time.Second)
		}},
		{mfaCaseExpired, func(_ *goauth.MFAEnrollmentConfirmRequest, e *goauth.MFAEnrollmentRecord) {
			e.ExpiresAt = e.CreatedAt
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeOptional)
			auth, _ := mfaOptionalSession(t, f)
			enrollment := mfaOptionalEnrollment(t, f, auth)
			request := mfaOptionalConfirmation(t, f, auth, enrollment)
			test.change(&request, &f.store.state.enrollment)
			before := f.store.state.clone()
			codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), request)
			require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
			require.Empty(t, codes)
			require.Equal(t, before, f.store.state)
		})
	}
}

func TestMFAOptionalConfirmationWrongCodeCommitsAttempt(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, _ := mfaOptionalSession(t, f)
	enrollment := mfaOptionalEnrollment(t, f, auth)
	request := mfaOptionalConfirmation(t, f, auth, enrollment)
	request.Code = mfaInvalidValue
	attempts := f.store.state.attempts
	codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, codes)
	require.Equal(t, attempts+1, f.store.state.attempts)
	require.Equal(t, enrollment.ID, f.store.state.enrollment.ID)
	require.False(t, f.store.state.factor.Enabled)

	request.Code = mfaFlowCode(t, enrollment.Secret, f.now)
	codes, err = f.runtime.ConfirmMFAEnrollment(t.Context(), request)
	require.NoError(t, err)
	mfaOptionalRecoveryDigests(t, f, codes)
}

func TestMFAOptionalConfirmationFailsClosedOnDamagedSecretOrBudget(t *testing.T) {
	for _, test := range []struct {
		name    string
		change  func(*mfaFlowFixture)
		wantErr error
	}{
		{"attempt budget exhausted", func(f *mfaFlowFixture) {
			f.store.attemptLimit = f.store.state.attempts
		}, goauth.ErrMFALoginDenied},
		{"ciphertext damaged", func(f *mfaFlowFixture) {
			f.store.state.enrollment.Ciphertext[0] ^= 1
		}, goauth.ErrMFAUnavailable},
		{"historical key missing", func(f *mfaFlowFixture) {
			f.store.state.enrollment.KeyID = "unavailable-key"
		}, goauth.ErrMFAUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeOptional)
			auth, tokens := mfaOptionalSession(t, f)
			enrollment := mfaOptionalEnrollment(t, f, auth)
			test.change(f)
			codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), mfaOptionalConfirmation(t, f, auth, enrollment))
			require.ErrorIs(t, err, test.wantErr)
			require.Empty(t, codes)
			require.False(t, f.store.state.factor.Enabled)
			_, err = f.runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
			require.NoError(t, err)
		})
	}
}

func TestMFAOptionalConfirmationStorageFailureRollsBack(t *testing.T) {
	for _, fault := range []string{
		mfaFaultLockFactor, "lock_enrollment", "take_attempt", "replace_factor", "replace_recovery", mfaFaultInvalidate, testAuditStage,
	} {
		t.Run(fault, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeOptional)
			auth, tokens := mfaOptionalSession(t, f)
			enrollment := mfaOptionalEnrollment(t, f, auth)
			f.store.faults[fault] = errMFAFlowCommit
			before := f.store.state.clone()
			codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), mfaOptionalConfirmation(t, f, auth, enrollment))
			require.ErrorIs(t, err, errMFAFlowCommit)
			require.Empty(t, codes)
			require.Equal(t, before, f.store.state)
			_, err = f.runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
			require.NoError(t, err)
		})
	}
}

func TestMFAOptionalConfirmationRejectsLostFactorCAS(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, _ := mfaOptionalSession(t, f)
	enrollment := mfaOptionalEnrollment(t, f, auth)
	f.store.reject["replace_factor"] = true
	before := f.store.state.clone()
	codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), mfaOptionalConfirmation(t, f, auth, enrollment))
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, codes)
	require.Equal(t, before, f.store.state)
}

func TestMFAOptionalEnrollmentCancellationIsSessionAndBrowserBound(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, tokens := mfaOptionalSession(t, f)
	enrollment := mfaOptionalEnrollment(t, f, auth)
	otherAuth, _ := mfaOptionalSession(t, f)
	require.NoError(t, f.runtime.CancelMFAEnrollment(t.Context(), otherAuth, f.binding))
	require.Equal(t, enrollment.ID, f.store.state.enrollment.ID)
	otherBinding := f.binding
	otherBinding[0]++
	require.NoError(t, f.runtime.CancelMFAEnrollment(t.Context(), auth, otherBinding))
	require.Equal(t, enrollment.ID, f.store.state.enrollment.ID)
	require.ErrorIs(t, f.runtime.CancelMFAEnrollment(t.Context(), auth, [32]byte{}), goauth.ErrMFALoginDenied)
	require.NoError(t, f.runtime.CancelMFAEnrollment(t.Context(), auth, f.binding))
	require.Empty(t, f.store.state.enrollment)
	require.NoError(t, f.runtime.CancelMFAEnrollment(t.Context(), auth, f.binding))
	_, err := f.runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
	require.NoError(t, err)
	codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), mfaOptionalConfirmation(t, f, auth, enrollment))
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, codes)
}

func TestMFAOptionalCancellationStorageErrors(t *testing.T) {
	for _, fault := range []string{mfaFaultLockFactor, "cancel_enrollment"} {
		t.Run(fault, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeOptional)
			auth, _ := mfaOptionalSession(t, f)
			mfaOptionalEnrollment(t, f, auth)
			f.store.faults[fault] = errMFAFlowCommit
			before := f.store.state.clone()
			err := f.runtime.CancelMFAEnrollment(t.Context(), auth, f.binding)
			require.ErrorIs(t, err, errMFAFlowCommit)
			require.Equal(t, before, f.store.state)
		})
	}
}

func TestMFAOptionalReplacementRequiresCurrentFactor(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, tokens := mfaOptionalSession(t, f)
	f.enableFactor(t)
	previous := f.store.state.factor
	request := goauth.MFAEnrollmentRequest{Auth: auth, Password: mfaFlowPassword, Binding: f.binding}
	enrollment, err := f.runtime.BeginMFAEnrollment(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, enrollment)
	require.Equal(t, previous, f.store.state.factor)
	require.Empty(t, f.store.state.enrollment)

	request.CurrentCode = mfaFlowCode(t, mfaFlowSecret, f.now)
	enrollment, err = f.runtime.BeginMFAEnrollment(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, previous.ID, f.store.state.factor.ID)
	require.Equal(t, previous.Revision, f.store.state.factor.Revision)
	require.Equal(t, f.now.Unix()/30, f.store.state.factor.LastStep)
	codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), mfaOptionalConfirmation(t, f, auth, enrollment))
	require.NoError(t, err)
	require.NotEqual(t, previous.ID, f.store.state.factor.ID)
	require.Equal(t, previous.Revision+1, f.store.state.factor.Revision)
	mfaOptionalRecoveryDigests(t, f, codes)
	mfaOptionalInvalidated(t, f, tokens, "mfa.enrolled")
}

func TestMFAOptionalRegenerateRecoveryInvalidatesOldCodesAndSessions(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, tokens := mfaOptionalSession(t, f)
	f.enableFactor(t)
	previous := f.store.state.factor
	f.begin(t)
	oldCode, err := goauth.NewMFARecoveryCode()
	require.NoError(t, err)
	oldDigest, err := f.codec.RecoveryDigest(f.account.Subject.ID, previous.ID, oldCode)
	require.NoError(t, err)
	f.store.state.recovery[string(oldDigest)] = true
	codes, err := f.runtime.RegenerateMFARecovery(t.Context(), goauth.MFAChangeRequest{
		Auth: auth, Password: mfaFlowPassword, Code: mfaFlowCode(t, mfaFlowSecret, f.now),
	})
	require.NoError(t, err)
	require.True(t, f.store.state.factor.Enabled)
	require.Equal(t, previous.ID, f.store.state.factor.ID)
	require.Equal(t, previous.Revision+1, f.store.state.factor.Revision)
	require.Equal(t, previous.Ciphertext, f.store.state.factor.Ciphertext)
	require.Equal(t, f.now.Unix()/30, f.store.state.factor.LastStep)
	require.NotContains(t, f.store.state.recovery, string(oldDigest))
	mfaOptionalRecoveryDigests(t, f, codes)
	mfaOptionalInvalidated(t, f, tokens, "mfa.recovery_regenerated")
	pending := f.begin(t)
	login, err := f.runtime.CompleteLocalLogin(t.Context(), pending.ID, f.binding, oldCode)
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, login)
	login, err = f.runtime.CompleteLocalLogin(t.Context(), pending.ID, f.binding, codes[0])
	require.NoError(t, err)
	require.NotEmpty(t, login.Tokens.AccessToken)
}

func TestMFAOptionalDisableClearsSecretsAndRevokesSessions(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, tokens := mfaOptionalSession(t, f)
	f.enableFactor(t)
	previous := f.store.state.factor
	f.begin(t)
	digest, err := f.codec.RecoveryDigest(f.account.Subject.ID, previous.ID, mfaFlowID(30))
	require.NoError(t, err)
	f.store.state.recovery[string(digest)] = true
	err = f.runtime.DisableMFA(t.Context(), goauth.MFAChangeRequest{
		Auth: auth, Password: mfaFlowPassword, Code: mfaFlowCode(t, mfaFlowSecret, f.now),
	})
	require.NoError(t, err)
	require.False(t, f.store.state.factor.Enabled)
	require.Equal(t, previous.ID, f.store.state.factor.ID)
	require.Equal(t, previous.Revision+1, f.store.state.factor.Revision)
	require.Empty(t, f.store.state.factor.KeyID)
	require.Empty(t, f.store.state.factor.Ciphertext)
	require.Equal(t, int64(-1), f.store.state.factor.LastStep)
	require.Empty(t, f.store.state.recovery)
	mfaOptionalInvalidated(t, f, tokens, "mfa.disabled")
	newAuth, _ := mfaOptionalSession(t, f)
	require.Equal(t, auth.SecurityVersion+1, newAuth.SecurityVersion)
}

func TestMFAOptionalChangesRejectInvalidProof(t *testing.T) {
	for _, test := range []struct {
		name    string
		change  func(*mfaFlowFixture, *goauth.MFAChangeRequest)
		wantErr error
	}{
		{"oversized code", func(_ *mfaFlowFixture, r *goauth.MFAChangeRequest) {
			r.Code = strings.Repeat("1", 129)
		}, goauth.ErrMFALoginDenied},
		{mfaCaseWrongPassword, func(_ *mfaFlowFixture, r *goauth.MFAChangeRequest) {
			r.Password = "incorrect"
		}, goauth.ErrCurrentPasswordInvalid},
		{"wrong factor", func(_ *mfaFlowFixture, r *goauth.MFAChangeRequest) {
			r.Code = mfaInvalidValue
		}, goauth.ErrMFALoginDenied},
		{"disabled factor", func(f *mfaFlowFixture, _ *goauth.MFAChangeRequest) {
			f.store.state.factor.Enabled = false
		}, goauth.ErrMFALoginDenied},
		{"replayed TOTP", func(f *mfaFlowFixture, _ *goauth.MFAChangeRequest) {
			f.store.state.factor.LastStep = f.now.Unix() / 30
		}, goauth.ErrMFALoginDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeOptional)
			auth, tokens := mfaOptionalSession(t, f)
			f.enableFactor(t)
			request := goauth.MFAChangeRequest{
				Auth: auth, Password: mfaFlowPassword, Code: mfaFlowCode(t, mfaFlowSecret, f.now),
			}
			test.change(f, &request)
			factor := f.store.state.factor
			codes, err := f.runtime.RegenerateMFARecovery(t.Context(), request)
			require.ErrorIs(t, err, test.wantErr)
			require.Empty(t, codes)
			require.Equal(t, factor, f.store.state.factor)
			_, err = f.runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
			require.NoError(t, err)
		})
	}
}

func TestMFAOptionalChangesStorageFailuresRollBack(t *testing.T) {
	for _, operation := range []string{"disable", "regenerate"} {
		for _, fault := range []string{
			mfaFaultLockFactor, "take_attempt", "advance_step", "replace_factor", "replace_recovery", mfaFaultInvalidate, testAuditStage,
		} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f := newMFAFlowFixture(t, goauth.MFAModeOptional)
				auth, tokens := mfaOptionalSession(t, f)
				f.enableFactor(t)
				f.store.faults[fault] = errMFAFlowCommit
				before := f.store.state.clone()
				request := goauth.MFAChangeRequest{
					Auth: auth, Password: mfaFlowPassword, Code: mfaFlowCode(t, mfaFlowSecret, f.now),
				}
				var err error
				if operation == "disable" {
					err = f.runtime.DisableMFA(t.Context(), request)
				} else {
					var codes []string
					codes, err = f.runtime.RegenerateMFARecovery(t.Context(), request)
					require.Empty(t, codes)
				}
				require.ErrorIs(t, err, errMFAFlowCommit)
				require.Equal(t, before, f.store.state)
				_, err = f.runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
				require.NoError(t, err)
			})
		}
	}
}

func TestMFAOptionalChangesRejectLostFactorCAS(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, _ := mfaOptionalSession(t, f)
	f.enableFactor(t)
	f.store.reject["replace_factor"] = true
	before := f.store.state.clone()
	err := f.runtime.DisableMFA(t.Context(), goauth.MFAChangeRequest{
		Auth: auth, Password: mfaFlowPassword, Code: mfaFlowCode(t, mfaFlowSecret, f.now),
	})
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Equal(t, before, f.store.state)
}

func TestMFAOptionalEnrollmentCommitErrorsWithholdResults(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		name := "rollback"
		if unknown {
			name = "unknown outcome"
		}
		t.Run(name, func(t *testing.T) {
			f := newMFAFlowFixture(t, goauth.MFAModeOptional)
			auth, _ := mfaOptionalSession(t, f)
			before := f.store.state.clone()
			wantErr := errMFAFlowCommit
			if unknown {
				f.store.unknownCommitAt = f.store.owned + 2
				f.store.commitErr = goauth.ErrOperationOutcomeUnknown
				wantErr = goauth.ErrOperationOutcomeUnknown
			} else {
				f.store.failCommitAt = f.store.owned + 2
			}
			enrollment, err := f.runtime.BeginMFAEnrollment(t.Context(), goauth.MFAEnrollmentRequest{
				Auth: auth, Password: mfaFlowPassword, Binding: f.binding,
			})
			require.ErrorIs(t, err, wantErr)
			require.Empty(t, enrollment)
			if unknown {
				require.NotEmpty(t, f.store.state.enrollment.ID)
			} else {
				require.Equal(t, before, f.store.state)
			}
		})
	}
}

func TestMFAOptionalConfirmationUnknownCommitWithholdsRecovery(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, tokens := mfaOptionalSession(t, f)
	enrollment := mfaOptionalEnrollment(t, f, auth)
	f.store.unknownCommitAt = f.store.owned + 2
	f.store.commitErr = goauth.ErrOperationOutcomeUnknown
	codes, err := f.runtime.ConfirmMFAEnrollment(t.Context(), mfaOptionalConfirmation(t, f, auth, enrollment))
	require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
	require.Empty(t, codes)
	require.True(t, f.store.state.factor.Enabled)
	require.Len(t, f.store.state.recovery, 10)
	mfaOptionalInvalidated(t, f, tokens, "mfa.enrolled")
}

func TestMFAOptionalRecoveryUnknownCommitWithholdsNewCodes(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, tokens := mfaOptionalSession(t, f)
	f.enableFactor(t)
	revision := f.store.state.factor.Revision
	f.store.unknownCommitAt = f.store.owned + 2
	f.store.commitErr = goauth.ErrOperationOutcomeUnknown
	codes, err := f.runtime.RegenerateMFARecovery(t.Context(), goauth.MFAChangeRequest{
		Auth: auth, Password: mfaFlowPassword, Code: mfaFlowCode(t, mfaFlowSecret, f.now),
	})
	require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
	require.Empty(t, codes)
	require.Equal(t, revision+1, f.store.state.factor.Revision)
	require.Len(t, f.store.state.recovery, 10)
	mfaOptionalInvalidated(t, f, tokens, "mfa.recovery_regenerated")
}

func TestMFAOptionalReauthenticationCannotOutliveItsWindow(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeOptional)
	auth, _ := mfaOptionalSession(t, f)
	commit := f.store.owned + 2
	f.store.beforeOwned = func(sequence int) {
		if sequence == commit {
			f.now = f.now.Add(5 * time.Minute)
		}
	}
	enrollment, err := f.runtime.BeginMFAEnrollment(t.Context(), goauth.MFAEnrollmentRequest{
		Auth: auth, Password: mfaFlowPassword, Binding: f.binding,
	})
	require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
	require.Empty(t, enrollment)
	require.Empty(t, f.store.state.enrollment)
}

func TestMFARequiredDisableForcesReenrollmentBeforeLocalAuthority(t *testing.T) {
	f := newMFAFlowFixture(t, goauth.MFAModeRequired)
	pending, enrollment := f.setup(t)
	login, err := f.runtime.CompleteLocalLoginEnrollment(t.Context(), pending.ID, enrollment.ID,
		f.binding, mfaFlowCode(t, enrollment.Secret, f.now))
	require.NoError(t, err)
	auth, err := f.runtime.AuthenticateSession(t.Context(), login.Tokens.AccessToken)
	require.NoError(t, err)
	err = f.runtime.DisableMFA(t.Context(), goauth.MFAChangeRequest{
		Auth: auth, Password: mfaFlowPassword, Code: enrollment.RecoveryCodes[0],
	})
	require.NoError(t, err)
	require.False(t, f.store.state.factor.Enabled)
	mfaOptionalInvalidated(t, f, login.Tokens, "mfa.disabled")

	passwordOnly, err := f.runtime.Login(t.Context(), f.request)
	require.ErrorIs(t, err, goauth.ErrMFARequired)
	require.Empty(t, passwordOnly)
	continuation := f.begin(t)
	require.Equal(t, goauth.MFALoginKindEnrollment, continuation.Kind)
	require.Len(t, f.store.state.sessions, 1, "reset must not issue another authenticated session")
}
