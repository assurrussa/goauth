package goauth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// LocalIdentityView is a safe identity read model, without credential material.
type LocalIdentityView struct {
	Account    Account
	Identifier Identifier
}

// RenameLocalIdentityRequest binds a custom login edit to the exact subject and
// security version the host authorized. Both identifiers use the same explicit,
// registered non-email scheme. ExpectedIdentifier is compared after normalization.
type RenameLocalIdentityRequest struct {
	SubjectID               SubjectID
	ExpectedIdentifier      IdentifierInput
	ExpectedSecurityVersion int64
	NewIdentifier           IdentifierInput
}

// RenameLocalIdentityStoreRequest contains already normalized, bounded values.
// Stores must validate these bounds and the expected state under a subject lock.
type RenameLocalIdentityStoreRequest struct {
	SubjectID               SubjectID
	Scheme                  IdentifierScheme
	ExpectedNormalizedValue string
	ExpectedSecurityVersion int64
	NewDisplayValue         string
	NewNormalizedValue      string
	Now                     time.Time
}

// LocalIdentifierReader is an optional read-only RuntimeStore capability. Return
// only the subject's primary custom identifier for the explicit non-email scheme,
// never a secondary alias or credential. Missing rows return ErrLocalIdentifierConflict.
// Reads must join an existing AuthTransaction and reject foreign transaction scopes.
type LocalIdentifierReader interface {
	GetLocalIdentifier(ctx context.Context, subjectID SubjectID, scheme IdentifierScheme) (Identifier, error)
}

// LocalIdentityRenameStore is an optional capability; required store interfaces
// remain unchanged. Lock subject before its identifier and credential; require an
// existing credential, compare security version then old normalized identifier.
// Preserve status, identifier ID/creation time, profile, email, links and credential.
// A real edit advances security version exactly once and invalidates sessions,
// local/OIDC families, resets and pending email security state in AuthTransaction.
// Exact no-ops return ErrIdentifierUnchanged after CAS without any writes. Collisions
// (including same-subject aliases) return ErrIdentifierAlreadyExists, never merge.
// Overflow fails closed. The Runtime adds mandatory audit to the same transaction.
type LocalIdentityRenameStore interface {
	RenameLocalIdentity(ctx context.Context, request RenameLocalIdentityStoreRequest) (LocalIdentityView, error)
}

var (
	ErrLocalIdentifierUnsupported     = errors.New("local identifier read capability is not supported")
	ErrLocalIdentityRenameUnsupported = errors.New("local identity rename capability is not supported")
	ErrLocalIdentifierConflict        = errors.New("local primary identifier is missing or changed")
	ErrIdentifierUnchanged            = errors.New("local identifier is unchanged")
)

// GetLocalIdentifier reads a primary custom login by immutable subject ID. It
// exposes neither passwords nor password policy, and does not require a credential.
// The scheme must be explicitly registered and non-email; absence is a conflict.
func (r *Runtime) GetLocalIdentifier(ctx context.Context, subjectID SubjectID, scheme IdentifierScheme) (Identifier, error) {
	reader, ok := r.store.(LocalIdentifierReader)
	if !ok {
		return Identifier{}, ErrLocalIdentifierUnsupported
	}
	if subjectID.IsZero() {
		return Identifier{}, ErrAccountNotFound
	}
	if err := r.localIdentifierScheme(scheme); err != nil {
		return Identifier{}, err
	}
	identifier, err := reader.GetLocalIdentifier(ctx, subjectID, scheme)
	if err != nil {
		return Identifier{}, fmt.Errorf("get local identifier: %w", err)
	}
	return identifier, nil
}

// RenameLocalIdentity is a privileged host operation, with no public endpoint or
// notification. Authorize the exact subject and rate-limit the operator first.
// Original display spelling is preserved; the registered resolver defines equality.
// Display-only edits also advance security version; an exact no-op is an error.
// Old login is immediately released, so reuse must create a fresh subject.
//
// Call before host project locks. Results inside an outer AuthTransaction are
// provisional until that transaction succeeds. ErrOperationOutcomeUnknown returns
// no success; reconcile a durable host receipt before retrying. Version increments
// invalidate existing bindings but do not close OIDC provider final-write races.
func (r *Runtime) RenameLocalIdentity(ctx context.Context, request RenameLocalIdentityRequest) (LocalIdentityView, error) {
	store, ok := r.store.(LocalIdentityRenameStore)
	if !ok {
		return LocalIdentityView{}, ErrLocalIdentityRenameUnsupported
	}
	if request.SubjectID.IsZero() {
		return LocalIdentityView{}, ErrAccountNotFound
	}
	if request.ExpectedSecurityVersion < 1 {
		return LocalIdentityView{}, ErrSecurityVersionMismatch
	}
	if request.ExpectedIdentifier.Scheme != request.NewIdentifier.Scheme {
		return LocalIdentityView{}, ErrInvalidIdentifierScheme
	}
	if err := r.localIdentifierScheme(request.ExpectedIdentifier.Scheme); err != nil {
		return LocalIdentityView{}, err
	}
	expected, err := r.normalizeLocalIdentifier(ctx, request.ExpectedIdentifier)
	if err != nil {
		return LocalIdentityView{}, err
	}
	next, err := r.normalizeLocalIdentifier(ctx, request.NewIdentifier)
	if err != nil {
		return LocalIdentityView{}, err
	}
	var view LocalIdentityView
	err = r.inSecurityTransaction(ctx, func(txCtx context.Context) error {
		changed, err := store.RenameLocalIdentity(txCtx, RenameLocalIdentityStoreRequest{
			SubjectID: request.SubjectID, Scheme: expected.Scheme,
			ExpectedNormalizedValue: expected.Value, ExpectedSecurityVersion: request.ExpectedSecurityVersion,
			NewDisplayValue: request.NewIdentifier.Value, NewNormalizedValue: next.Value, Now: r.now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("rename local identity: %w", err)
		}
		if err := r.recordAudit(txCtx, SecurityEvent{
			Type: SecurityEventLocalIdentityRenamed, SubjectID: request.SubjectID, At: r.now().UTC(),
		}); err != nil {
			return err
		}
		view = changed
		return nil
	})
	if err != nil {
		return LocalIdentityView{}, err
	}
	return view, nil
}

func (r *Runtime) localIdentifierScheme(scheme IdentifierScheme) error {
	if scheme == "" || scheme == IdentifierSchemeEmail {
		return ErrInvalidIdentifierScheme
	}
	if _, ok := r.identifiers[scheme]; !ok {
		return ErrInvalidIdentifierScheme
	}
	return nil
}

func (r *Runtime) normalizeLocalIdentifier(ctx context.Context, input IdentifierInput) (IdentifierInput, error) {
	if !validLocalIdentifier(input.Value) {
		return IdentifierInput{}, ErrInvalidIdentifier
	}
	normalized, err := r.normalizeIdentifier(ctx, input)
	if err != nil {
		return IdentifierInput{}, err
	}
	if !validLocalIdentifier(normalized.Value) {
		return IdentifierInput{}, ErrInvalidIdentifier
	}
	return normalized, nil
}
