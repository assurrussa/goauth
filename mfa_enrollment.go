package goauth

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const mfaEnrollmentLifetime = 5 * time.Minute

// AuthContext comes from verified host authentication, never untrusted JSON.
func (r *Runtime) lockMFASession(ctx context.Context, auth AuthContext) (Account, error) {
	if auth.SubjectID.IsZero() || auth.SessionID == "" || auth.Scope != SessionScopeAuthenticated {
		return Account{}, ErrMFALoginDenied
	}
	account, err := r.lockActiveAccount(ctx, auth.SubjectID)
	if err != nil {
		return Account{}, err
	}
	state, err := r.store.IntrospectSession(ctx, auth.SessionID)
	if err != nil {
		return Account{}, err
	}
	now := r.now()
	if !state.Session.Active(now) || state.SubjectStatus != SubjectStatusActive ||
		state.Session.SubjectID != auth.SubjectID || state.Session.Realm != auth.Realm ||
		state.Session.Scope != SessionScopeAuthenticated || state.Session.SecurityVersion != auth.SecurityVersion ||
		state.CurrentVersion != auth.SecurityVersion || account.Subject.SecurityVersion != auth.SecurityVersion {
		return Account{}, ErrMFALoginDenied
	}
	if _, err := r.authorizeRealm(ctx, auth.Realm, account); err != nil {
		return Account{}, err
	}
	return account, nil
}

type mfaReauthentication struct {
	account   Account
	expiresAt time.Time
}

func (r *Runtime) prepareMFAReauthentication(ctx context.Context, auth AuthContext,
	password string,
) (mfaReauthentication, error) {
	if r.mfaStore == nil || r.mfaCodec == nil {
		return mfaReauthentication{}, ErrMFAUnavailable
	}
	var account Account
	err := r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		var err error
		account, err = r.lockMFASession(txctx, auth)
		return err
	})
	if err != nil {
		return mfaReauthentication{}, err
	}
	if err := r.limitPasswordChange(ctx, account.Subject.ID); err != nil {
		return mfaReauthentication{}, err
	}
	record, err := r.store.GetLocalAccount(ctx, account.Subject.ID)
	if err != nil {
		return mfaReauthentication{}, err
	}
	if !sameMFALoginAccount(record.Account, account) {
		return mfaReauthentication{}, ErrSecurityVersionMismatch
	}
	if err := r.hasher.verifyCredential(record.PasswordPHC, password, record.PasswordInputPolicy); err != nil {
		if isPasswordVerificationFailure(err) {
			return mfaReauthentication{}, err
		}
		return mfaReauthentication{}, ErrCurrentPasswordInvalid
	}
	return mfaReauthentication{account: account, expiresAt: r.now().Add(5 * time.Minute)}, nil
}

// MFAStatus reports enrollment and whether local MFA management is available.
// A missing codec still returns the authorized enrollment state with ErrMFAUnavailable.
func (r *Runtime) MFAStatus(ctx context.Context, auth AuthContext) (bool, error) {
	if r.mfaStore == nil {
		return false, ErrMFAUnavailable
	}
	var enabled bool
	err := r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		account, err := r.lockMFASession(txctx, auth)
		if err != nil {
			return err
		}
		factor, err := r.mfaStore.LockMFAFactor(txctx, account.Subject.ID)
		if err != nil {
			return err
		}
		enabled = factor.Enabled
		if r.mfaCodec == nil {
			return ErrMFAUnavailable
		}
		if enabled {
			return r.mfaCodec.CheckKey(factor.KeyID)
		}
		return nil
	})
	return enabled, err
}

func (r *Runtime) BeginMFAEnrollment(ctx context.Context, request MFAEnrollmentRequest) (MFAEnrollment, error) {
	var empty [32]byte
	if request.Binding == empty || len(request.CurrentCode) > 128 {
		return MFAEnrollment{}, ErrMFALoginDenied
	}
	expected, err := r.prepareMFAReauthentication(ctx, request.Auth, request.Password)
	if err != nil {
		return MFAEnrollment{}, err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: r.jwt.config.Issuer, AccountName: expected.account.Subject.ID.String(),
		SecretSize: 32, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return MFAEnrollment{}, ErrMFAUnavailable
	}
	id, err := NewMFALoginID()
	if err != nil {
		return MFAEnrollment{}, err
	}
	keyID, ciphertext, err := r.mfaCodec.Seal(expected.account.Subject.ID, id, key.Secret())
	if err != nil {
		return MFAEnrollment{}, err
	}
	var result MFAEnrollment
	denied := false
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		current, err := r.lockMFASession(txctx, request.Auth)
		if err != nil {
			return err
		}
		if !sameMFALoginAccount(current, expected.account) || !r.now().Before(expected.expiresAt) {
			return ErrSecurityVersionMismatch
		}
		factor, err := r.mfaStore.EnsureMFAFactor(txctx, current.Subject.ID)
		if err != nil {
			return err
		}
		admitted, err := r.admitMFAEnrollment(txctx, current.Subject.ID, factor, request.CurrentCode)
		if err != nil {
			return err
		}
		if !admitted {
			denied = true
			return nil
		}
		now := r.now().UTC()
		expires := now.Add(mfaEnrollmentLifetime)
		record := MFAEnrollmentRecord{
			SubjectID: current.Subject.ID, ID: id, Revision: factor.Revision,
			SecurityVersion: current.Subject.SecurityVersion, SessionID: request.Auth.SessionID, Binding: request.Binding,
			KeyID: keyID, Ciphertext: ciphertext, CreatedAt: now, ExpiresAt: expires,
		}
		if err := r.mfaStore.SaveMFAEnrollment(txctx, record); err != nil {
			return err
		}
		result = MFAEnrollment{ID: id, Secret: key.Secret(), URL: key.URL(), ExpiresAt: expires}
		return nil
	})
	if err != nil {
		return MFAEnrollment{}, err
	}
	if denied || !r.now().Before(result.ExpiresAt) {
		return MFAEnrollment{}, ErrMFALoginDenied
	}
	return result, nil
}

func (r *Runtime) ConfirmMFAEnrollment(ctx context.Context, request MFAEnrollmentConfirmRequest) ([]string, error) {
	if !validMFALoginID(request.EnrollmentID) || len(request.Code) > 128 {
		return nil, ErrMFALoginDenied
	}
	expected, err := r.prepareMFAReauthentication(ctx, request.Auth, request.Password)
	if err != nil {
		return nil, err
	}
	var codes []string
	denied := false
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		current, err := r.lockMFASession(txctx, request.Auth)
		if err != nil {
			return err
		}
		if !sameMFALoginAccount(current, expected.account) || !r.now().Before(expected.expiresAt) {
			return ErrSecurityVersionMismatch
		}
		factor, err := r.mfaStore.LockMFAFactor(txctx, current.Subject.ID)
		if err != nil {
			return err
		}
		enrollment, err := r.mfaStore.LockMFAEnrollment(txctx, current.Subject.ID)
		if err != nil {
			return err
		}
		if !validMFAEnrollment(enrollment, request, current, factor, r.now()) {
			return ErrMFALoginDenied
		}
		step, valid, err := r.verifyMFAEnrollmentCode(txctx, current.Subject.ID, enrollment, request.Code)
		if err != nil {
			return err
		}
		if !valid {
			denied = true
			return nil
		}
		replacement := MFAFactorRecord{
			ID: enrollment.ID, Revision: factor.Revision + 1, Enabled: true,
			KeyID: enrollment.KeyID, Ciphertext: enrollment.Ciphertext, LastStep: step,
		}
		changed, err := r.mfaStore.ReplaceMFAFactor(txctx, current.Subject.ID, factor, replacement)
		if err != nil {
			return err
		}
		if !changed {
			return ErrMFALoginDenied
		}
		codes, err = r.replaceMFARecovery(txctx, current.Subject.ID, replacement.ID)
		if err != nil {
			return err
		}
		if !r.now().Before(enrollment.ExpiresAt) {
			return ErrMFALoginDenied
		}
		return r.invalidateMFAAuthentication(txctx, current.Subject.ID, "mfa.enrolled")
	})
	if err != nil {
		return nil, err
	}
	if denied {
		return nil, ErrMFALoginDenied
	}
	return codes, nil
}

func (r *Runtime) CancelMFAEnrollment(ctx context.Context, auth AuthContext, binding [32]byte) error {
	if r.mfaStore == nil {
		return ErrMFAUnavailable
	}
	var empty [32]byte
	if binding == empty {
		return ErrMFALoginDenied
	}
	return r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		account, err := r.lockMFASession(txctx, auth)
		if err != nil {
			return err
		}
		if _, err := r.mfaStore.LockMFAFactor(txctx, account.Subject.ID); err != nil {
			return err
		}
		return r.mfaStore.CancelMFAEnrollment(txctx, account.Subject.ID, auth.SessionID, binding)
	})
}

func (r *Runtime) DisableMFA(ctx context.Context, request MFAChangeRequest) error {
	_, err := r.changeMFA(ctx, request, false)
	return err
}

func (r *Runtime) RegenerateMFARecovery(ctx context.Context, request MFAChangeRequest) ([]string, error) {
	return r.changeMFA(ctx, request, true)
}

func (r *Runtime) changeMFA(ctx context.Context, request MFAChangeRequest, recovery bool) ([]string, error) {
	if len(request.Code) > 128 {
		return nil, ErrMFALoginDenied
	}
	expected, err := r.prepareMFAReauthentication(ctx, request.Auth, request.Password)
	if err != nil {
		return nil, err
	}
	var codes []string
	denied := false
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		current, err := r.lockMFASession(txctx, request.Auth)
		if err != nil {
			return err
		}
		if !sameMFALoginAccount(current, expected.account) || !r.now().Before(expected.expiresAt) {
			return ErrSecurityVersionMismatch
		}
		factor, err := r.mfaStore.LockMFAFactor(txctx, current.Subject.ID)
		if err != nil {
			return err
		}
		if !factor.Enabled {
			denied = true
			return nil
		}
		decision, err := VerifyMFAFactorLocked(txctx, r.mfaStore, r.mfaCodec, current.Subject.ID, factor, request.Code, r.now())
		if err != nil {
			return err
		}
		if decision != MFAFactorVerified {
			denied = true
			return nil
		}
		// Preserve the step advanced by the just-consumed TOTP.
		consumed, err := r.mfaStore.LockMFAFactor(txctx, current.Subject.ID)
		if err != nil {
			return err
		}
		replacement := consumed
		replacement.Revision++
		action := "mfa.recovery_regenerated"
		if !recovery {
			replacement.Enabled = false
			replacement.KeyID = ""
			replacement.Ciphertext = nil
			replacement.LastStep = -1
			action = "mfa.disabled"
		}
		changed, err := r.mfaStore.ReplaceMFAFactor(txctx, current.Subject.ID, consumed, replacement)
		if err != nil {
			return err
		}
		if !changed {
			return ErrMFALoginDenied
		}
		if recovery {
			codes, err = r.replaceMFARecovery(txctx, current.Subject.ID, replacement.ID)
		} else {
			err = r.mfaStore.ReplaceMFARecovery(txctx, current.Subject.ID, nil)
		}
		if err != nil {
			return err
		}
		return r.invalidateMFAAuthentication(txctx, current.Subject.ID, action)
	})
	if err != nil {
		return nil, err
	}
	if denied {
		return nil, ErrMFALoginDenied
	}
	return codes, nil
}

func (r *Runtime) replaceMFARecovery(ctx context.Context, subject SubjectID, factorID string) ([]string, error) {
	codes := make([]string, 10)
	digests := make([][]byte, len(codes))
	for i := range codes {
		var err error
		codes[i], err = NewMFARecoveryCode()
		if err != nil {
			return nil, err
		}
		digests[i], err = r.mfaCodec.RecoveryDigest(subject, factorID, codes[i])
		if err != nil {
			return nil, err
		}
	}
	if err := r.mfaStore.ReplaceMFARecovery(ctx, subject, digests); err != nil {
		return nil, err
	}
	return codes, nil
}

func (r *Runtime) invalidateMFAAuthentication(ctx context.Context, subject SubjectID, action string) error {
	if err := r.mfaStore.InvalidateMFAState(ctx, subject); err != nil {
		return err
	}
	if _, err := r.LogoutAll(ctx, subject); err != nil {
		return err
	}
	return r.recordAudit(ctx, SecurityEvent{Type: SecurityEventType(action), SubjectID: subject, At: r.now().UTC()})
}

func (r *Runtime) admitMFAEnrollment(
	ctx context.Context, subject SubjectID, factor MFAFactorRecord, code string,
) (bool, error) {
	if !factor.Enabled {
		return r.mfaStore.TakeMFAAttempt(ctx, subject)
	}
	decision, err := VerifyMFAFactorLocked(ctx, r.mfaStore, r.mfaCodec, subject, factor, code, r.now())
	return decision == MFAFactorVerified, err
}

func validMFAEnrollment(
	enrollment MFAEnrollmentRecord, request MFAEnrollmentConfirmRequest,
	account Account, factor MFAFactorRecord, now time.Time,
) bool {
	var empty [32]byte
	return request.Binding != empty && enrollment.SubjectID == account.Subject.ID &&
		enrollment.ID == request.EnrollmentID && enrollment.SessionID == request.Auth.SessionID &&
		enrollment.Revision == factor.Revision && enrollment.SecurityVersion == account.Subject.SecurityVersion &&
		subtle.ConstantTimeCompare(enrollment.Binding[:], request.Binding[:]) == 1 &&
		!enrollment.CreatedAt.After(now) && now.Before(enrollment.ExpiresAt)
}

func (r *Runtime) verifyMFAEnrollmentCode(
	ctx context.Context, subject SubjectID, enrollment MFAEnrollmentRecord, code string,
) (int64, bool, error) {
	admitted, err := r.mfaStore.TakeMFAAttempt(ctx, subject)
	if err != nil {
		return 0, false, err
	}
	if !admitted {
		return 0, false, nil
	}
	plain, err := r.mfaCodec.Open(subject, enrollment.ID, enrollment.KeyID, enrollment.Ciphertext)
	if err != nil {
		return 0, false, err
	}
	defer clear(plain)
	step, valid, err := MFATOTPStep(string(plain), code, r.now())
	if err != nil {
		return 0, false, ErrMFAUnavailable
	}
	return step, valid, nil
}
