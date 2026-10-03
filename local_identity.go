package goauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/assurrussa/goauth/internal/identifierbounds"
)

// PasswordInputPolicy describes verification of an existing credential, never
// issuance of a new password. The zero value retains the standard Unicode policy.
type PasswordInputPolicy string

const (
	PasswordInputPolicyUnicode PasswordInputPolicy = "unicode_v1"
	// PasswordInputPolicyLegacyBytes256 is only for explicitly imported Argon2id
	// v19 credentials with m=65536,t=3,p=1, a 16-byte salt and a 32-byte digest.
	PasswordInputPolicyLegacyBytes256 PasswordInputPolicy = "legacy_bytes_256" //nolint:gosec // Policy identifier, not a credential.
)

// LocalIdentityRecord is a create-only, email-less account with one custom login
// identifier. The identifier is not an email or a verification assertion.
type LocalIdentityRecord struct {
	LocalAccountRecord
	Identifier Identifier
}

// LocalIdentityStore is an optional capability for privileged local identities.
// Implementations must persist PasswordInputPolicy, return it on every credential
// read, and clear it to Unicode on password change/reset. Creates must reject any
// existing subject or identifier, never merge, and join AuthTransaction.
type LocalIdentityStore interface {
	CreateLocalIdentity(ctx context.Context, record LocalIdentityRecord) (Account, error)
}

// ProvisionLocalIdentityRequest creates an active email-less local identity.
// Identifier must use an explicitly registered non-email scheme.
type ProvisionLocalIdentityRequest struct {
	Identifier IdentifierInput
	Password   string
	Profile    BasicProfile
}

// ImportLocalIdentityRequest imports one existing email-less local identity.
// SubjectID is assigned by the host's durable migration mapping. Status must be
// explicit. PHCs must be canonical and match the configured current profile, or
// the fixed legacy profile when EnableLegacyBytes256 is enabled.
type ImportLocalIdentityRequest struct {
	SubjectID           SubjectID
	Identifier          IdentifierInput
	PasswordPHC         string
	PasswordInputPolicy PasswordInputPolicy
	Profile             BasicProfile
	Status              SubjectStatus
}

var ErrLocalIdentityUnsupported = errors.New("local identity capability is not supported")

// ProvisionLocalIdentity is a privileged host API. Authorize the operator before
// calling it; do not bind public signup input to it. It creates no session and
// asserts no verified email. Account creation and audit join AuthTransaction.
func (r *Runtime) ProvisionLocalIdentity(ctx context.Context, request ProvisionLocalIdentityRequest) (Account, error) {
	if _, ok := r.store.(LocalIdentityStore); !ok {
		return Account{}, ErrLocalIdentityUnsupported
	}
	if err := r.passwordPolicy.Validate(request.Password); err != nil {
		return Account{}, err
	}
	record, err := r.prepareLocalIdentity(ctx, NewSubjectID(), request.Identifier, request.Profile, SubjectStatusActive)
	if err != nil {
		return Account{}, err
	}
	record.PasswordPHC, err = r.hasher.HashPassword(request.Password)
	if err != nil {
		return Account{}, fmt.Errorf("hash local identity password: %w", err)
	}
	record.PasswordInputPolicy = PasswordInputPolicyUnicode
	return r.createLocalIdentity(ctx, record, SecurityEventLocalIdentityProvisioned)
}

// ImportLocalIdentity is a privileged, create-only migration API. It never
// overwrites passwords, re-enables subjects, or merges identities by identifier.
// The host must atomically persist its import mapping and grants using the same
// AuthTransaction and skip already mapped imports, preserving later mutations.
// A conflict is an error, including a repeated call with the same subject ID.
func (r *Runtime) ImportLocalIdentity(ctx context.Context, request ImportLocalIdentityRequest) (Account, error) {
	if _, ok := r.store.(LocalIdentityStore); !ok {
		return Account{}, ErrLocalIdentityUnsupported
	}
	if !r.hasher.supportsImport() {
		return Account{}, ErrLocalIdentityUnsupported
	}
	if request.PasswordInputPolicy == "" {
		request.PasswordInputPolicy = PasswordInputPolicyUnicode
	}
	if err := r.hasher.validateImport(request.PasswordPHC, request.PasswordInputPolicy); err != nil {
		return Account{}, err
	}
	record, err := r.prepareLocalIdentity(ctx, request.SubjectID, request.Identifier, request.Profile, request.Status)
	if err != nil {
		return Account{}, err
	}
	record.PasswordPHC = request.PasswordPHC
	record.PasswordInputPolicy = request.PasswordInputPolicy
	return r.createLocalIdentity(ctx, record, SecurityEventLocalIdentityImported)
}

func (r *Runtime) prepareLocalIdentity(ctx context.Context, id SubjectID, input IdentifierInput,
	profile BasicProfile, status SubjectStatus,
) (LocalIdentityRecord, error) {
	if err := id.Validate(); err != nil {
		return LocalIdentityRecord{}, err
	}
	if err := status.Validate(); err != nil {
		return LocalIdentityRecord{}, err
	}
	if input.Scheme == "" || input.Scheme == IdentifierSchemeEmail {
		return LocalIdentityRecord{}, ErrInvalidIdentifierScheme
	}
	normalized, err := r.normalizeIdentifier(ctx, input)
	if err != nil {
		return LocalIdentityRecord{}, err
	}
	// PostgreSQL TEXT requires UTF-8 without NUL; bound index and audit-independent
	// identifier storage even when a custom resolver omits its own input bounds.
	if !validLocalIdentifier(input.Value) || !validLocalIdentifier(normalized.Value) {
		return LocalIdentityRecord{}, ErrInvalidIdentifier
	}
	now := r.now().UTC()
	return LocalIdentityRecord{
		LocalAccountRecord: LocalAccountRecord{Account: Account{Subject: Subject{
			ID: id, Status: status,
			SecurityVersion: 1, CreatedAt: now, UpdatedAt: now,
		}, Profile: profile}},
		Identifier: Identifier{
			ID: uuid.NewString(), SubjectID: id, Scheme: input.Scheme,
			DisplayValue: input.Value, NormalizedValue: normalized.Value, CreatedAt: now, UpdatedAt: now,
		},
	}, nil
}

func validLocalIdentifier(value string) bool {
	return identifierbounds.Valid(value)
}

func (r *Runtime) createLocalIdentity(ctx context.Context, record LocalIdentityRecord, event SecurityEventType) (Account, error) {
	store, ok := r.store.(LocalIdentityStore)
	if !ok {
		return Account{}, ErrLocalIdentityUnsupported
	}
	var account Account
	err := r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		var err error
		account, err = store.CreateLocalIdentity(ctx, record)
		if err != nil {
			return err
		}
		return r.recordAudit(ctx, SecurityEvent{Type: event, SubjectID: account.Subject.ID, At: r.now().UTC()})
	})
	if err != nil {
		return Account{}, err
	}
	return account, nil
}
