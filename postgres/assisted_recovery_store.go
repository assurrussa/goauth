package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/assurrussa/goauth"
)

// Assisted recovery writes require the caller's owned security transaction so
// its audit, MFA attempt state and encrypted notifications commit together.
func (s *Store) assistedRecoveryTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.notificationTx(ctx)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, errors.New("assisted recovery requires an auth transaction")
	}
	return tx, nil
}

func (s *Store) CreateAssistedRecovery(ctx context.Context, record goauth.AssistedRecoveryRecord) error {
	if record.SubjectID.IsZero() || record.ActorID.IsZero() || record.Selector == "" || record.Digest.KeyID == "" ||
		len(record.Digest.Digest) != 32 || record.SecurityVersion < 1 || record.TargetVersion < 1 || record.CreatedAt.IsZero() ||
		!record.ExpiresAt.After(record.CreatedAt) || record.ExpiresAt.Sub(record.CreatedAt) > goauth.AssistedRecoveryLifetime {
		return goauth.ErrAssistedRecoveryDenied
	}
	oldEmail, err := goauth.NormalizeEmail(record.OldEmail)
	if err != nil || oldEmail != record.OldEmail {
		return goauth.ErrAssistedRecoveryDenied
	}
	newEmail, err := goauth.NormalizeEmail(record.NewEmail)
	if err != nil || newEmail != record.NewEmail || newEmail == oldEmail {
		return goauth.ErrAssistedRecoveryDenied
	}
	tx, err := s.assistedRecoveryTx(ctx)
	if err != nil {
		return err
	}
	if err := lockActiveSubject(ctx, tx, record.SubjectID); err != nil {
		return err
	}
	account, err := getAccount(ctx, tx, record.SubjectID)
	if err != nil {
		return err
	}
	if account.Subject.SecurityVersion != record.SecurityVersion ||
		(record.Scope == "" && account.PrimaryEmail.NormalizedValue != record.OldEmail) {
		return goauth.ErrSecurityVersionMismatch
	}
	var existingCredential bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM auth_local_credentials WHERE subject_id=$1 AND password_phc<>'')`,
		record.SubjectID).Scan(&existingCredential); err != nil {
		return err
	}
	if !existingCredential {
		return goauth.ErrAccountNotFound
	}
	var occupied bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM auth_identifiers WHERE scheme='email' AND normalized_value=$1)`,
		record.NewEmail).Scan(&occupied); err != nil {
		return err
	}
	if occupied {
		return goauth.ErrIdentifierAlreadyExists
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO auth_assisted_recovery
 (selector,subject_id,actor_id,key_id,secret_digest,security_version,old_email,new_email,created_at,
 expires_at,scope,target_version,owner_cli)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
 ON CONFLICT(subject_id) DO UPDATE SET selector=EXCLUDED.selector,actor_id=EXCLUDED.actor_id,
 key_id=EXCLUDED.key_id,secret_digest=EXCLUDED.secret_digest,security_version=EXCLUDED.security_version,
 old_email=EXCLUDED.old_email,new_email=EXCLUDED.new_email,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at,
 scope=EXCLUDED.scope,target_version=EXCLUDED.target_version,owner_cli=EXCLUDED.owner_cli`,
		record.Selector, record.SubjectID, record.ActorID, record.Digest.KeyID, record.Digest.Digest,
		record.SecurityVersion, record.OldEmail, record.NewEmail, record.CreatedAt, record.ExpiresAt,
		record.Scope, record.TargetVersion, record.OwnerCLI)
	return err
}

func (s *Store) FindAssistedRecoverySubject(ctx context.Context, selector string) (goauth.SubjectID, error) {
	var subject goauth.SubjectID
	err := s.queryer(ctx).QueryRowContext(ctx,
		`SELECT subject_id FROM auth_assisted_recovery WHERE selector=$1`,
		selector).Scan(&subject)
	if errors.Is(err, sql.ErrNoRows) {
		return subject, goauth.ErrAssistedRecoveryDenied
	}
	return subject, err
}

func (s *Store) LockAssistedRecovery(ctx context.Context, selector string) (goauth.AssistedRecoveryRecord, error) {
	var record goauth.AssistedRecoveryRecord
	tx, err := s.assistedRecoveryTx(ctx)
	if err != nil {
		return record, err
	}
	err = tx.QueryRowContext(ctx,
		`SELECT selector,subject_id,actor_id,key_id,secret_digest,security_version,old_email,new_email,
 created_at,expires_at,scope,target_version,owner_cli
 FROM auth_assisted_recovery WHERE selector=$1 FOR UPDATE`, selector).Scan(&record.Selector, &record.SubjectID,
		&record.ActorID, &record.Digest.KeyID, &record.Digest.Digest, &record.SecurityVersion,
		&record.OldEmail, &record.NewEmail, &record.CreatedAt, &record.ExpiresAt, &record.Scope,
		&record.TargetVersion, &record.OwnerCLI)
	if errors.Is(err, sql.ErrNoRows) {
		return record, goauth.ErrAssistedRecoveryDenied
	}
	return record, err
}

func (s *Store) CompleteAssistedRecovery(
	ctx context.Context, record goauth.AssistedRecoveryRecord, passwordPHC string, now time.Time,
) (goauth.Account, error) {
	if passwordPHC == "" || now.IsZero() || !now.Before(record.ExpiresAt) {
		return goauth.Account{}, goauth.ErrAssistedRecoveryDenied
	}
	tx, err := s.assistedRecoveryTx(ctx)
	if err != nil {
		return goauth.Account{}, err
	}
	if err := lockActiveSubject(ctx, tx, record.SubjectID); err != nil {
		return goauth.Account{}, err
	}
	// The exact row is consumed in the same transaction as both credential
	// changes. Concurrent completions and superseded/stale invitations lose CAS.
	result, err := tx.ExecContext(ctx, `DELETE FROM auth_assisted_recovery r USING auth_subjects s
 WHERE r.selector=$1 AND r.subject_id=$2 AND r.actor_id=$3 AND r.key_id=$4 AND r.secret_digest=$5
 AND r.security_version=$6 AND r.old_email=$7 AND r.new_email=$8 AND r.created_at=$9 AND r.expires_at=$10
 AND r.expires_at>$11 AND s.id=r.subject_id AND s.status='active' AND s.retired_at IS NULL
 AND s.security_version=r.security_version AND r.scope=$12 AND r.target_version=$13 AND r.owner_cli=$14
 AND (r.scope<>'' OR EXISTS(SELECT 1 FROM auth_identifiers i WHERE i.subject_id=s.id AND i.scheme='email'
 AND i.is_primary AND i.normalized_value=r.old_email))`, record.Selector, record.SubjectID, record.ActorID,
		record.Digest.KeyID, record.Digest.Digest, record.SecurityVersion, record.OldEmail, record.NewEmail,
		record.CreatedAt, record.ExpiresAt, now, record.Scope, record.TargetVersion, record.OwnerCLI)
	if err != nil {
		return goauth.Account{}, err
	}
	if err := assistedRecoveryExactlyOne(result); err != nil {
		return goauth.Account{}, err
	}
	result, err = tx.ExecContext(ctx,
		`UPDATE auth_local_credentials SET password_phc=$2,password_input_policy='unicode_v1',updated_at=$3
 WHERE subject_id=$1 AND password_phc<>''`,
		record.SubjectID, passwordPHC, now)
	if err != nil {
		return goauth.Account{}, err
	}
	if err := assistedRecoveryExactlyOne(result); err != nil {
		return goauth.Account{}, err
	}
	if record.Scope == "" {
		result, err = tx.ExecContext(ctx,
			`UPDATE auth_identifiers SET display_value=$2,normalized_value=$2,verified_at=$3,updated_at=$3
 WHERE subject_id=$1 AND scheme='email' AND is_primary AND normalized_value=$4`,
			record.SubjectID, record.NewEmail, now, record.OldEmail)
		if err != nil {
			return goauth.Account{}, transformWriteError("replace assisted recovery email", err)
		}
		if err := assistedRecoveryExactlyOne(result); err != nil {
			return goauth.Account{}, err
		}
	}
	result, err = tx.ExecContext(ctx, `UPDATE auth_subjects SET security_version=security_version+1,updated_at=$3
 WHERE id=$1 AND security_version=$2 AND status='active' AND retired_at IS NULL`, record.SubjectID, record.SecurityVersion, now)
	if err != nil {
		return goauth.Account{}, err
	}
	if err := assistedRecoveryExactlyOne(result); err != nil {
		return goauth.Account{}, err
	}
	if _, err := revokeSubjectSecurityState(ctx, tx, record.SubjectID, now); err != nil {
		return goauth.Account{}, err
	}
	if err := invalidatePasswordResets(ctx, tx, record.SubjectID, now); err != nil {
		return goauth.Account{}, err
	}
	// Keep enrolled factors and unconsumed MFA recovery codes intact. The new
	// security version fences login continuations and outstanding invitations.
	return getAccount(ctx, tx, record.SubjectID)
}

func assistedRecoveryExactlyOne(result sql.Result) error {
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return goauth.ErrAssistedRecoveryDenied
	}
	return nil
}

var _ goauth.AssistedRecoveryStore = (*Store)(nil)
