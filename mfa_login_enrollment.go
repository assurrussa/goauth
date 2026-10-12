package goauth

import (
	"context"
	"math"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// BeginLocalLoginEnrollment only accepts a live password-verified enrollment
// continuation. It never creates a session or extends the original deadline.
func (r *Runtime) BeginLocalLoginEnrollment(ctx context.Context, id string, binding [32]byte) (MFAEnrollment, error) {
	store, err := r.requiredEnrollmentStore()
	if err != nil {
		return MFAEnrollment{}, err
	}
	if !validMFALoginID(id) {
		return MFAEnrollment{}, ErrMFALoginDenied
	}
	subject, err := store.FindMFALoginSubject(ctx, id)
	if err != nil {
		return MFAEnrollment{}, err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: r.jwt.config.Issuer, AccountName: subject.String(),
		SecretSize: 32, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return MFAEnrollment{}, ErrMFAUnavailable
	}
	setup, codes, err := r.newMFALoginSetup(subject, key.Secret())
	if err != nil {
		return MFAEnrollment{}, err
	}
	var result MFAEnrollment
	decision := MFAFactorDenied
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		account, factor, pending, err := r.lockMFALogin(txctx, subject, id)
		if err != nil {
			return err
		}
		if err := r.validateEnrollmentLogin(txctx, account, factor, pending, binding); err != nil {
			return err
		}
		admitted, err := store.TakeMFAAttempt(txctx, subject)
		if err != nil {
			return err
		}
		if !admitted {
			decision = MFAFactorRateLimited
			return nil
		}
		if err := store.SaveMFALoginSetup(txctx, pending, setup); err != nil {
			return err
		}
		if !r.now().Before(pending.ExpiresAt) {
			return ErrMFALoginDenied
		}
		result = MFAEnrollment{ID: setup.ID, Secret: key.Secret(), URL: key.URL(), ExpiresAt: pending.ExpiresAt, RecoveryCodes: codes}
		decision = MFAFactorVerified
		return nil
	})
	if err != nil {
		return MFAEnrollment{}, err
	}
	if err := r.mfaEnrollmentDecision(decision, result.ExpiresAt); err != nil {
		return MFAEnrollment{}, err
	}
	return result, nil
}

func (r *Runtime) requiredEnrollmentStore() (MFARequiredStore, error) {
	if r.mfaMode != MFAModeRequired {
		return nil, ErrMFALoginDenied
	}
	store, ok := r.mfaStore.(MFARequiredStore)
	if !ok || r.mfaCodec == nil {
		return nil, ErrMFAUnavailable
	}
	return store, nil
}

func (r *Runtime) validateEnrollmentLogin(ctx context.Context, account Account, factor MFAFactorRecord,
	pending MFALoginPending, binding [32]byte,
) error {
	if r.mfaMode != MFAModeRequired {
		return ErrMFALoginDenied
	}
	if err := validateMFALoginPurpose(
		pending, account, factor, pending.Realm, binding, r.now(), MFALoginKindEnrollment,
	); err != nil {
		return err
	}
	if err := r.validateRealm(pending.Realm); err != nil {
		return err
	}
	_, err := r.authorizeRealm(ctx, pending.Realm, account)
	return err
}

func (r *Runtime) newMFALoginSetup(subject SubjectID, secret string) (MFALoginSetup, []string, error) {
	id, err := NewMFALoginID()
	if err != nil {
		return MFALoginSetup{}, nil, err
	}
	keyID, ciphertext, err := r.mfaCodec.Seal(subject, id, secret)
	if err != nil {
		return MFALoginSetup{}, nil, err
	}
	setup := MFALoginSetup{ID: id, KeyID: keyID, Ciphertext: ciphertext, RecoveryDigests: make([][]byte, 10)}
	codes := make([]string, 10)
	for i := range codes {
		codes[i], err = NewMFARecoveryCode()
		if err != nil {
			return MFALoginSetup{}, nil, err
		}
		setup.RecoveryDigests[i], err = r.mfaCodec.RecoveryDigest(subject, id, codes[i])
		if err != nil {
			return MFALoginSetup{}, nil, err
		}
	}
	return setup, codes, nil
}

// CompleteLocalLoginEnrollment atomically activates the displayed setup,
// invalidates previous authority and publishes a fresh post-enrollment session.
// No authority or recovery codes are returned for an uncertain commit.
func (r *Runtime) CompleteLocalLoginEnrollment(
	ctx context.Context, id, enrollmentID string, binding [32]byte, code string,
) (LoginResult, error) {
	if _, err := r.requiredEnrollmentStore(); err != nil {
		return LoginResult{}, err
	}
	if !validMFALoginID(id) || !validMFALoginID(enrollmentID) || len(code) > 128 {
		return LoginResult{}, ErrMFALoginDenied
	}
	subject, err := r.mfaStore.FindMFALoginSubject(ctx, id)
	if err != nil {
		return LoginResult{}, err
	}
	var account Account
	var pending MFALoginPending
	var scope SessionScope
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		var factor MFAFactorRecord
		var err error
		account, factor, pending, err = r.lockMFALogin(txctx, subject, id)
		if err != nil {
			return err
		}
		if err := r.validateEnrollmentLogin(txctx, account, factor, pending, binding); err != nil {
			return err
		}
		if pending.Setup.ID != enrollmentID || len(pending.Setup.RecoveryDigests) != 10 {
			return ErrMFALoginDenied
		}
		scope, err = r.authorizeRealm(txctx, pending.Realm, account)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	if account.Subject.SecurityVersion == math.MaxInt64 {
		return LoginResult{}, ErrMFAUnavailable
	}
	nextAccount := account
	nextAccount.Subject.SecurityVersion++
	prepared, err := r.prepareSession(ctx, nextAccount, pending.Realm, scope)
	if err != nil {
		return LoginResult{}, err
	}
	prepared.mfaAdmission = MFASessionAdmissionFactor
	decision := MFAFactorDenied
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		var err error
		decision, err = r.completeEnrollmentLoginLocked(txctx, account, pending, binding, code, scope, prepared)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	if err := r.mfaEnrollmentDecision(decision, pending.ExpiresAt); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Account: nextAccount, Tokens: prepared.tokens}, nil
}

func (r *Runtime) completeEnrollmentLoginLocked(
	ctx context.Context, account Account, pending MFALoginPending, binding [32]byte, code string,
	scope SessionScope, prepared preparedSession,
) (MFAFactorDecision, error) {
	current, factor, locked, err := r.lockMFALogin(ctx, pending.SubjectID, pending.ID)
	if err != nil {
		return MFAFactorDenied, err
	}
	if !sameMFALoginAccount(current, account) {
		return MFAFactorDenied, ErrSecurityVersionMismatch
	}
	if err := r.validateEnrollmentLogin(ctx, current, factor, locked, binding); err != nil {
		return MFAFactorDenied, err
	}
	if locked.Setup.ID != pending.Setup.ID || len(locked.Setup.RecoveryDigests) != 10 {
		return MFAFactorDenied, ErrMFALoginDenied
	}
	currentScope, err := r.authorizeRealm(ctx, locked.Realm, current)
	if err != nil {
		return MFAFactorDenied, err
	}
	if currentScope != scope {
		return MFAFactorDenied, ErrSecurityVersionMismatch
	}
	decision, step, err := r.verifyLoginSetupLocked(ctx, current.Subject.ID, locked.Setup, code)
	if err != nil || decision != MFAFactorVerified {
		return decision, err
	}
	replacement := MFAFactorRecord{
		ID: locked.Setup.ID, Revision: factor.Revision + 1, Enabled: true,
		KeyID: locked.Setup.KeyID, Ciphertext: locked.Setup.Ciphertext, LastStep: step,
	}
	changed, err := r.mfaStore.ReplaceMFAFactor(ctx, current.Subject.ID, factor, replacement)
	if err != nil {
		return MFAFactorDenied, err
	}
	if !changed {
		return MFAFactorDenied, ErrMFALoginDenied
	}
	if err := r.mfaStore.ReplaceMFARecovery(ctx, current.Subject.ID, locked.Setup.RecoveryDigests); err != nil {
		return MFAFactorDenied, err
	}
	consumed, err := r.mfaStore.ConsumeMFALogin(ctx, locked)
	if err != nil {
		return MFAFactorDenied, err
	}
	if !consumed {
		return MFAFactorDenied, ErrMFALoginDenied
	}
	if err := r.invalidateMFAAuthentication(ctx, current.Subject.ID, "mfa.enrolled"); err != nil {
		return MFAFactorDenied, err
	}
	updated, err := r.lockActiveAccount(ctx, current.Subject.ID)
	if err != nil {
		return MFAFactorDenied, err
	}
	expected := current
	expected.Subject.SecurityVersion++
	if !sameMFALoginAccount(updated, expected) || !r.now().Before(locked.ExpiresAt) {
		return MFAFactorDenied, ErrMFALoginDenied
	}
	if err := r.createPreparedSession(ctx, prepared); err != nil {
		return MFAFactorDenied, err
	}
	return MFAFactorVerified, r.recordAudit(ctx, SecurityEvent{
		Type: SecurityEventType("mfa.login"), SubjectID: current.Subject.ID, Realm: locked.Realm, At: r.now().UTC(),
	})
}

func (r *Runtime) verifyLoginSetupLocked(
	ctx context.Context, subject SubjectID, setup MFALoginSetup, code string,
) (MFAFactorDecision, int64, error) {
	admitted, err := r.mfaStore.TakeMFAAttempt(ctx, subject)
	if err != nil {
		return MFAFactorDenied, 0, err
	}
	if !admitted {
		return MFAFactorRateLimited, 0, nil
	}
	plain, err := r.mfaCodec.Open(subject, setup.ID, setup.KeyID, setup.Ciphertext)
	if err != nil {
		return MFAFactorDenied, 0, err
	}
	defer clear(plain)
	step, valid, err := MFATOTPStep(string(plain), code, r.now())
	if err != nil {
		return MFAFactorDenied, 0, ErrMFAUnavailable
	}
	if !valid {
		return MFAFactorDenied, 0, nil
	}
	return MFAFactorVerified, step, nil
}

func (r *Runtime) mfaEnrollmentDecision(decision MFAFactorDecision, expires time.Time) error {
	if decision == MFAFactorRateLimited {
		return r.limited(ErrAuthenticationRateLimited, r.now().Add(5*time.Minute))
	}
	if decision != MFAFactorVerified || !r.now().Before(expires) {
		return ErrMFALoginDenied
	}
	return nil
}
