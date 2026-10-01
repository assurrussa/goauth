package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/assurrussa/goauth"
)

// CredentialProof is an opaque, short-lived credential verification bound to
// one runtime. It contains no password and can only be prepared by that runtime.
type CredentialProof struct {
	runtime   *Runtime
	account   goauth.Account
	expiresAt time.Time
}

// PrepareCredential performs durable rate admission and password verification
// before the host's outer transaction. The proof expires after five minutes.
func (r *Runtime) PrepareCredential(ctx context.Context, credential goauth.Credential) (*CredentialProof, error) {
	if r == nil || r.Runtime == nil {
		return nil, errors.New("PostgreSQL Runtime is not initialized")
	}
	account, err := r.VerifyCredential(ctx, credential)
	if err != nil {
		return nil, err
	}
	return &CredentialProof{runtime: r, account: account, expiresAt: time.Now().Add(5 * time.Minute)}, nil
}

// RevalidateCredential requires this runtime's managed transaction and holds the
// canonical subject lock until the outer commit. Security version, active status
// and normalized primary email must still match the verified proof before a host
// can grant membership. Callers must never substitute request-supplied accounts.
func (r *Runtime) RevalidateCredential(ctx context.Context, proof *CredentialProof) (goauth.Account, error) {
	if r == nil || r.store == nil {
		return goauth.Account{}, errors.New("PostgreSQL Runtime is not initialized")
	}
	if proof == nil || proof.runtime != r || !time.Now().Before(proof.expiresAt) {
		return goauth.Account{}, goauth.ErrInvalidCredentials
	}
	tx, err := r.store.notificationTx(ctx)
	if err != nil {
		return goauth.Account{}, err
	}
	if tx == nil {
		return goauth.Account{}, errors.New("credential revalidation requires managed auth transaction")
	}
	var subject goauth.SubjectID
	if err := tx.QueryRowContext(ctx, "SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE",
		proof.account.Subject.ID).Scan(&subject); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return goauth.Account{}, goauth.ErrInvalidCredentials
		}
		return goauth.Account{}, fmt.Errorf("lock verified subject: %w", err)
	}
	// A lock wait must not extend the proof's recent-authentication window.
	if !time.Now().Before(proof.expiresAt) {
		return goauth.Account{}, goauth.ErrInvalidCredentials
	}
	account, err := r.GetAccount(ctx, subject)
	if err != nil {
		return goauth.Account{}, err
	}
	if account.Subject.ID != proof.account.Subject.ID || account.Subject.Status != goauth.SubjectStatusActive ||
		account.Subject.SecurityVersion != proof.account.Subject.SecurityVersion ||
		account.PrimaryEmail.NormalizedValue != proof.account.PrimaryEmail.NormalizedValue {
		return goauth.Account{}, goauth.ErrInvalidCredentials
	}
	return account, nil
}
