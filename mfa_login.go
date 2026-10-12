package goauth

import (
	"context"
	"errors"
	"time"
)

type MFALoginChallenge struct {
	Kind      MFALoginKind
	ID        string
	ExpiresAt time.Time
}
type LocalLoginResult struct {
	Login   LoginResult
	Pending *MFALoginChallenge
}
type ownedMFATransaction interface {
	InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error
}

func (r *Runtime) inOwnedMFATransaction(ctx context.Context, fn func(context.Context) error) error {
	owner, ok := r.authTransaction.(ownedMFATransaction)
	if !ok {
		return ErrMFAUnavailable
	}
	return owner.InOwnedAuthTransaction(ctx, fn)
}

func (r *Runtime) checkLocalMFA(ctx context.Context, subject SubjectID) error {
	if r.mfaMode == MFAModeRequired {
		return ErrMFARequired
	}
	admission, ok := r.store.(MFALocalAdmissionStore)
	if !ok {
		return nil
	}
	required, err := admission.LocalMFARequired(ctx, subject)
	if err != nil {
		return err
	}
	if required {
		return ErrMFARequired
	}
	return nil
}

// BeginLocalLogin returns either final local tokens or a non-authorizing pending
// selector. Hosts keep it separate from authenticated browser state and enforce
// their authoritative browser-flow publication fence before exposing tokens.
func (r *Runtime) BeginLocalLogin(ctx context.Context, request LoginRequest, binding [32]byte) (LocalLoginResult, error) {
	account, realm, scope, err := r.verifyLocalLogin(ctx, request)
	if err != nil {
		return LocalLoginResult{}, err
	}
	if r.mfaStore == nil {
		result, err := r.issueLoginSession(ctx, account, realm, scope)
		return LocalLoginResult{Login: result}, err
	}
	authenticated := r.now().UTC()
	var pending *MFALoginChallenge
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		current, err := r.lockActiveAccount(txctx, account.Subject.ID)
		if err != nil {
			return err
		}
		if !sameMFALoginAccount(current, account) {
			return ErrSecurityVersionMismatch
		}
		factor, kind, err := r.prepareMFALoginFactor(txctx, current.Subject.ID)
		if err != nil {
			return err
		}
		if kind == "" {
			return nil
		}
		var empty [32]byte
		if binding == empty {
			return ErrMFALoginDenied
		}
		id, err := NewMFALoginID()
		if err != nil {
			return err
		}
		now := r.now().UTC()
		if !now.Before(authenticated.Add(MFALoginLifetime)) {
			return ErrMFALoginDenied
		}
		record := MFALoginPending{
			ID: id, Kind: kind, SubjectID: current.Subject.ID, Realm: realm,
			SecurityVersion: current.Subject.SecurityVersion, FactorID: factor.ID,
			FactorRevision: factor.Revision, BindingDigest: binding,
			AuthenticatedAt: authenticated, ExpiresAt: authenticated.Add(MFALoginLifetime),
		}
		if err := r.mfaStore.CreateMFALogin(txctx, record); err != nil {
			return err
		}
		pending = &MFALoginChallenge{ID: id, Kind: kind, ExpiresAt: record.ExpiresAt}
		return nil
	})
	if err != nil {
		return LocalLoginResult{}, err
	}
	if pending != nil {
		if !r.now().Before(pending.ExpiresAt) {
			return LocalLoginResult{}, ErrMFALoginDenied
		}
		return LocalLoginResult{Pending: pending}, nil
	}
	// Final issuance rechecks enrollment under the subject lock.
	result, err := r.issueLoginSession(ctx, account, realm, scope)
	return LocalLoginResult{Login: result}, err
}

// prepareMFALoginFactor runs after locking and revalidating the account in the
// owned login transaction. An empty kind means optional MFA is not enrolled.
func (r *Runtime) prepareMFALoginFactor(
	ctx context.Context, subject SubjectID,
) (MFAFactorRecord, MFALoginKind, error) {
	factor, err := r.mfaStore.LockMFAFactor(ctx, subject)
	if err != nil {
		return MFAFactorRecord{}, "", err
	}
	if !factor.Enabled && r.mfaMode != MFAModeRequired {
		return factor, "", nil
	}
	kind := MFALoginKindFactor
	if !factor.Enabled {
		kind = MFALoginKindEnrollment
		factor, err = r.mfaStore.EnsureMFAFactor(ctx, subject)
		if err != nil {
			return MFAFactorRecord{}, "", err
		}
	}
	if r.mfaCodec == nil {
		return MFAFactorRecord{}, "", ErrMFAUnavailable
	}
	if factor.Enabled {
		if err := r.mfaCodec.CheckKey(factor.KeyID); err != nil {
			return MFAFactorRecord{}, "", err
		}
	}
	return factor, kind, nil
}

// CompleteLocalLogin prepares tokens before writes, then rechecks and consumes
// the factor/challenge with session and audit in one owned commit. Expected
// denials commit their durable attempt effects; errors release no usable result.
func (r *Runtime) CompleteLocalLogin(ctx context.Context, id string, binding [32]byte, code string) (LoginResult, error) {
	if r.mfaStore == nil || r.mfaCodec == nil {
		return LoginResult{}, ErrMFAUnavailable
	}
	if !validMFALoginID(id) || len(code) > 128 {
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
		if err := ValidateMFALoginPending(pending, account, factor, pending.Realm, binding, r.now()); err != nil {
			return err
		}
		if err := r.validateRealm(pending.Realm); err != nil {
			return err
		}
		scope, err = r.authorizeRealm(txctx, pending.Realm, account)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	prepared, err := r.prepareSession(ctx, account, pending.Realm, scope)
	if err != nil {
		return LoginResult{}, err
	}
	decision := MFAFactorDenied
	err = r.inOwnedMFATransaction(ctx, func(txctx context.Context) error {
		var err error
		decision, err = r.completeMFALoginLocked(txctx, account, pending, binding, code, scope, prepared)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	if decision == MFAFactorRateLimited {
		return LoginResult{}, r.limited(ErrAuthenticationRateLimited, r.now().Add(5*time.Minute))
	}
	if decision != MFAFactorVerified || !r.now().Before(pending.ExpiresAt) {
		return LoginResult{}, ErrMFALoginDenied
	}
	return LoginResult{Account: account, Tokens: prepared.tokens}, nil
}

// completeMFALoginLocked keeps final admission, consumption, session and audit
// in the caller-owned transaction. Its decision is provisional until commit.
func (r *Runtime) completeMFALoginLocked(
	ctx context.Context, account Account, pending MFALoginPending, binding [32]byte,
	code string, scope SessionScope, prepared preparedSession,
) (MFAFactorDecision, error) {
	current, factor, locked, err := r.lockMFALogin(ctx, pending.SubjectID, pending.ID)
	if err != nil {
		return MFAFactorDenied, err
	}
	if !sameMFALoginAccount(current, account) {
		return MFAFactorDenied, ErrSecurityVersionMismatch
	}
	if err := ValidateMFALoginPending(locked, current, factor, pending.Realm, binding, r.now()); err != nil {
		return MFAFactorDenied, err
	}
	currentScope, err := r.authorizeRealm(ctx, locked.Realm, current)
	if err != nil {
		return MFAFactorDenied, err
	}
	if currentScope != scope {
		return MFAFactorDenied, ErrSecurityVersionMismatch
	}
	decision, err := VerifyMFAFactorLocked(ctx, r.mfaStore, r.mfaCodec, pending.SubjectID, factor, code, r.now())
	if err != nil {
		return MFAFactorDenied, err
	}
	if decision != MFAFactorVerified {
		return decision, nil
	}
	consumed, err := r.mfaStore.ConsumeMFALogin(ctx, locked)
	if err != nil {
		return MFAFactorDenied, err
	}
	if !consumed || !r.now().Before(locked.ExpiresAt) {
		return MFAFactorDenied, ErrMFALoginDenied
	}
	prepared.mfaAdmission = MFASessionAdmissionFactor
	if err := r.createPreparedSession(ctx, prepared); err != nil {
		return MFAFactorDenied, err
	}
	err = r.recordAudit(ctx, SecurityEvent{
		Type: SecurityEventType("mfa.login"), SubjectID: pending.SubjectID, Realm: pending.Realm, At: r.now().UTC(),
	})
	return MFAFactorVerified, err
}

func (r *Runtime) lockMFALogin(
	ctx context.Context, subject SubjectID, id string,
) (Account, MFAFactorRecord, MFALoginPending, error) {
	account, err := r.lockActiveAccount(ctx, subject)
	if err != nil {
		return Account{}, MFAFactorRecord{}, MFALoginPending{}, err
	}
	factor, err := r.mfaStore.LockMFAFactor(ctx, subject)
	if err != nil {
		return Account{}, MFAFactorRecord{}, MFALoginPending{}, err
	}
	pending, err := r.mfaStore.LockMFALogin(ctx, id)
	if err != nil {
		return Account{}, MFAFactorRecord{}, MFALoginPending{}, err
	}
	if pending.SubjectID != subject {
		return Account{}, MFAFactorRecord{}, MFALoginPending{}, ErrMFALoginDenied
	}
	return account, factor, pending, nil
}

func sameMFALoginAccount(a, b Account) bool {
	return a.Subject.ID == b.Subject.ID && a.Subject.SecurityVersion == b.Subject.SecurityVersion &&
		a.PrimaryEmail.ID == b.PrimaryEmail.ID && a.PrimaryEmail.SubjectID == b.PrimaryEmail.SubjectID &&
		a.PrimaryEmail.Scheme == b.PrimaryEmail.Scheme && a.PrimaryEmail.NormalizedValue == b.PrimaryEmail.NormalizedValue &&
		a.EmailVerified() == b.EmailVerified()
}

func validateMFAConfig(config Config) error {
	if err := validateMFAMode(config); err != nil {
		return err
	}
	if config.MFAKeys == nil {
		return nil
	}
	if _, ok := config.Store.(MFAStore); !ok {
		return errors.New("MFA requires transactional factor and login store")
	}
	if _, ok := config.AuthTransaction.(ownedMFATransaction); !ok {
		return errors.New("MFA requires owned auth transactions")
	}
	if _, err := NewMFAFactorCodec(*config.MFAKeys, "goauth/mfa"); err != nil {
		return err
	}
	rings := []KeyRing{config.Signing.Keys, config.TokenHMACKeys, *config.MFAKeys}
	if len(config.OutboxAEADKeys.IDs()) != 0 {
		rings = append(rings, config.OutboxAEADKeys)
	}
	return validateDistinctKeyRings(rings...)
}
