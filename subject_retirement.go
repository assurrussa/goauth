package goauth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// SubjectLifecycleView is a non-secret, consistent snapshot of an account and
// its terminal retirement marker. Subject's existing struct layout is unchanged.
// RetiredAt is nil for ordinary active, suspended and disabled accounts.
type SubjectLifecycleView struct {
	Account   Account
	RetiredAt *time.Time
}

// RetireLocalIdentityRequest authorizes terminal retirement of the ENTIRE
// authentication subject, releasing only this primary custom login. Other
// identifiers and external links remain reserved to the disabled old subject.
type RetireLocalIdentityRequest struct {
	SubjectID               SubjectID
	ExpectedIdentifier      IdentifierInput
	ExpectedSecurityVersion int64
}

// RetireLocalIdentityStoreRequest contains an explicit non-email scheme and
// normalized, bounded expected login. Now must be nonzero.
type RetireLocalIdentityStoreRequest struct {
	SubjectID               SubjectID
	Scheme                  IdentifierScheme
	ExpectedNormalizedValue string
	ExpectedSecurityVersion int64
	Now                     time.Time
}

// SubjectLifecycleReader is an optional capability. Read account and marker from
// ONE consistent snapshot by immutable subject ID, including retired accounts.
// Reads join AuthTransaction and reject foreign transaction scopes.
type SubjectLifecycleReader interface {
	GetSubjectLifecycle(ctx context.Context, subjectID SubjectID) (SubjectLifecycleView, error)
}

// LocalIdentityRetirementStore is an optional capability; required store
// interfaces remain unchanged. Lock subject first, reject retirement, then check
// version, exact primary custom login and existing local credential. Atomically
// mark disabled/retired, increment once (including ordinary-disabled subjects),
// delete ONLY the selected identifier and the local credential, revoke sessions,
// local/OIDC families, resets and pending email security state. Keep UUID,
// profile, audit, RBAC, every other identifier and external link. Overflow denies.
// Return persisted timestamps. The Runtime adds mandatory transactional audit.
//
// Implementing this capability requires terminality across ALL store mutation
// paths: status/rename/password/credential/link writes cannot revive or attach
// authentication to a retired subject. Never clear the marker or reuse its ID.
// Retained bindings are deny-only, never reassigned or silently linked. Stores
// that cannot enforce these requirements must not advertise this capability.
type LocalIdentityRetirementStore interface {
	RetireLocalIdentity(ctx context.Context, request RetireLocalIdentityStoreRequest) (SubjectLifecycleView, error)
}

var (
	ErrSubjectLifecycleUnsupported        = errors.New("subject lifecycle read capability is not supported")
	ErrLocalIdentityRetirementUnsupported = errors.New("local identity retirement capability is not supported")
	ErrSubjectRetired                     = errors.New("authentication subject is permanently retired")
)

// GetSubjectLifecycle reads lifecycle by immutable subject ID. It is suitable
// for host reconciliation, but is not an operation receipt or proof of which
// request committed. It exposes no credentials.
func (r *Runtime) GetSubjectLifecycle(ctx context.Context, id SubjectID) (SubjectLifecycleView, error) {
	reader, ok := r.store.(SubjectLifecycleReader)
	if !ok {
		return SubjectLifecycleView{}, ErrSubjectLifecycleUnsupported
	}
	if id.IsZero() {
		return SubjectLifecycleView{}, ErrAccountNotFound
	}
	view, err := reader.GetSubjectLifecycle(ctx, id)
	if err != nil {
		return SubjectLifecycleView{}, fmt.Errorf("get subject lifecycle: %w", err)
	}
	return view, nil
}

// RetireLocalIdentity is a privileged host operation, without an HTTP endpoint
// or email notification. Authorize the exact subject, login and security version
// and rate-limit the operator first. This permanently retires the whole auth
// subject, not only an alias. Reusing the released login creates a fresh subject
// with no inherited grants, roles, sessions or links. Retained emails can prevent
// reuse and must never silently bind the replacement to the former subject.
//
// Call before host project locks and compose grants/audit/operation receipt in
// the same AuthTransaction. Nested results are provisional until outer commit.
// Every error returns zero success. ErrOperationOutcomeUnknown needs durable
// receipt reconciliation; do not blindly retry. Repeated retirement returns
// ErrSubjectRetired without writes. This does not close OIDC final-write races.
func (r *Runtime) RetireLocalIdentity(ctx context.Context, request RetireLocalIdentityRequest) (SubjectLifecycleView, error) {
	store, ok := r.store.(LocalIdentityRetirementStore)
	if !ok {
		return SubjectLifecycleView{}, ErrLocalIdentityRetirementUnsupported
	}
	if request.SubjectID.IsZero() {
		return SubjectLifecycleView{}, ErrAccountNotFound
	}
	if request.ExpectedSecurityVersion < 1 {
		return SubjectLifecycleView{}, ErrSecurityVersionMismatch
	}
	if err := r.localIdentifierScheme(request.ExpectedIdentifier.Scheme); err != nil {
		return SubjectLifecycleView{}, err
	}
	expected, err := r.normalizeLocalIdentifier(ctx, request.ExpectedIdentifier)
	if err != nil {
		return SubjectLifecycleView{}, err
	}
	var view SubjectLifecycleView
	err = r.inSecurityTransaction(ctx, func(txCtx context.Context) error {
		changed, err := store.RetireLocalIdentity(txCtx, RetireLocalIdentityStoreRequest{
			SubjectID: request.SubjectID, Scheme: expected.Scheme, ExpectedNormalizedValue: expected.Value,
			ExpectedSecurityVersion: request.ExpectedSecurityVersion, Now: r.now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("retire local identity: %w", err)
		}
		if err := r.recordAudit(txCtx, SecurityEvent{
			Type: SecurityEventSubjectRetired, SubjectID: request.SubjectID, At: r.now().UTC(),
		}); err != nil {
			return err
		}
		view = changed
		return nil
	})
	if err != nil {
		return SubjectLifecycleView{}, err
	}
	return view, nil
}
