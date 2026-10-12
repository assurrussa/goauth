package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/assurrussa/goauth"
)

func (s *Store) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	return s.inAuthTransaction(ctx, fn, true)
}

func (s *Store) mfaTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.notificationTx(ctx)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, errors.New("MFA requires managed auth transaction")
	}
	return tx, nil
}

func (s *Store) LocalMFARequired(ctx context.Context, subject goauth.SubjectID) (bool, error) {
	factor, err := s.LockMFAFactor(ctx, subject)
	return factor.Enabled, err
}

func (s *Store) LockMFAFactor(ctx context.Context, subject goauth.SubjectID) (goauth.MFAFactorRecord, error) {
	var factor goauth.MFAFactorRecord
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return factor, err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return factor, err
	}
	err = tx.QueryRowContext(ctx, `SELECT factor_id,revision,enabled,key_id,secret,last_step
 FROM auth_mfa_factors WHERE subject_id=$1 FOR UPDATE`, subject).
		Scan(&factor.ID, &factor.Revision, &factor.Enabled, &factor.KeyID, &factor.Ciphertext, &factor.LastStep)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.MFAFactorRecord{}, nil
	}
	return factor, err
}

func (s *Store) TakeMFAAttempt(ctx context.Context, subject goauth.SubjectID) (bool, error) {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return false, err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return false, err
	}
	var admitted bool
	err = tx.QueryRowContext(ctx, `WITH admitted AS (
 INSERT INTO auth_mfa_budget(subject_id,window_at,attempts) VALUES($1,clock_timestamp(),1)
 ON CONFLICT(subject_id) DO UPDATE SET
 attempts=CASE WHEN auth_mfa_budget.window_at<=EXCLUDED.window_at-interval '5 minutes'
 THEN 1 ELSE auth_mfa_budget.attempts+1 END,
 window_at=CASE WHEN auth_mfa_budget.window_at<=EXCLUDED.window_at-interval '5 minutes'
 THEN EXCLUDED.window_at ELSE auth_mfa_budget.window_at END
 WHERE auth_mfa_budget.window_at<=EXCLUDED.window_at-interval '5 minutes' OR auth_mfa_budget.attempts<10
 RETURNING subject_id) SELECT EXISTS(SELECT 1 FROM admitted)`, subject).Scan(&admitted)
	return admitted, err
}

func (s *Store) ConsumeMFARecovery(ctx context.Context, subject goauth.SubjectID, factorID string,
	revision int64, digest []byte,
) (bool, error) {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return false, err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM auth_mfa_recovery r USING auth_mfa_factors f
 WHERE r.subject_id=$1 AND r.digest=$4 AND f.subject_id=r.subject_id
 AND f.factor_id=$2 AND f.revision=$3 AND f.enabled`, subject, factorID, revision, digest)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (s *Store) AdvanceMFAStep(ctx context.Context, subject goauth.SubjectID, factorID string, revision,
	previous, next int64,
) (bool, error) {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return false, err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth_mfa_factors SET last_step=$5
 WHERE subject_id=$1 AND factor_id=$2 AND revision=$3 AND enabled AND last_step=$4 AND last_step<$5`,
		subject, factorID, revision, previous, next)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (s *Store) FindMFALoginSubject(ctx context.Context, id string) (goauth.SubjectID, error) {
	var subject goauth.SubjectID
	err := s.queryer(ctx).QueryRowContext(ctx, `SELECT subject_id FROM auth_mfa_pending WHERE id=$1`, id).Scan(&subject)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.NilSubjectID, goauth.ErrMFALoginDenied
	}
	return subject, err
}

func (s *Store) CreateMFALogin(ctx context.Context, pending goauth.MFALoginPending) error {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return err
	}
	if err := lockActiveSubject(ctx, tx, pending.SubjectID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO auth_mfa_pending
 (id,subject_id,realm,security_version,factor_id,factor_revision,binding,authenticated_at,expires_at,kind)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10 FROM auth_subjects a JOIN auth_mfa_factors f ON f.subject_id=a.id
 WHERE a.id=$2 AND a.security_version=$4 AND a.status='active' AND f.factor_id=$5 AND f.revision=$6
 AND (($10='factor' AND f.enabled) OR ($10='enrollment' AND NOT f.enabled))
 ON CONFLICT(subject_id,realm) DO UPDATE SET id=EXCLUDED.id,security_version=EXCLUDED.security_version,
 factor_id=EXCLUDED.factor_id,factor_revision=EXCLUDED.factor_revision,binding=EXCLUDED.binding,
 authenticated_at=EXCLUDED.authenticated_at,expires_at=EXCLUDED.expires_at,kind=EXCLUDED.kind,
 setup_id='',setup_key_id='',setup_secret='',setup_recovery=''`,
		pending.ID, pending.SubjectID, pending.Realm, pending.SecurityVersion, pending.FactorID,
		pending.FactorRevision, pending.BindingDigest[:], pending.AuthenticatedAt, pending.ExpiresAt, mfaPendingKind(pending.Kind))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return goauth.ErrMFALoginDenied
	}
	return nil
}

func (s *Store) LockMFALogin(ctx context.Context, id string) (goauth.MFALoginPending, error) {
	var pending goauth.MFALoginPending
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return pending, err
	}
	var binding, recovery []byte
	err = tx.QueryRowContext(ctx, `SELECT id,subject_id,realm,security_version,factor_id,factor_revision,
 binding,authenticated_at,expires_at,kind,setup_id,setup_key_id,setup_secret,setup_recovery
 FROM auth_mfa_pending WHERE id=$1 FOR UPDATE`, id).
		Scan(&pending.ID, &pending.SubjectID, &pending.Realm, &pending.SecurityVersion, &pending.FactorID,
			&pending.FactorRevision, &binding, &pending.AuthenticatedAt, &pending.ExpiresAt, &pending.Kind,
			&pending.Setup.ID, &pending.Setup.KeyID, &pending.Setup.Ciphertext, &recovery)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.MFALoginPending{}, goauth.ErrMFALoginDenied
	}
	if err != nil {
		return goauth.MFALoginPending{}, err
	}
	if len(binding) != len(pending.BindingDigest) {
		return goauth.MFALoginPending{}, goauth.ErrMFALoginDenied
	}
	copy(pending.BindingDigest[:], binding)
	if err := scanMFALoginSetup(&pending.Setup, recovery); err != nil {
		return goauth.MFALoginPending{}, err
	}
	return pending, nil
}

func (s *Store) ConsumeMFALogin(ctx context.Context, pending goauth.MFALoginPending) (bool, error) {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return false, err
	}
	if err := lockActiveSubject(ctx, tx, pending.SubjectID); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM auth_mfa_pending WHERE
 id=$1 AND subject_id=$2 AND realm=$3 AND security_version=$4 AND factor_id=$5 AND factor_revision=$6
 AND binding=$7 AND authenticated_at=$8 AND expires_at=$9 AND kind=$10 AND setup_id=$11`,
		pending.ID, pending.SubjectID, pending.Realm, pending.SecurityVersion, pending.FactorID,
		pending.FactorRevision, pending.BindingDigest[:], pending.AuthenticatedAt, pending.ExpiresAt,
		mfaPendingKind(pending.Kind), pending.Setup.ID)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

var _ goauth.MFAStore = (*Store)(nil)

func mfaPendingKind(kind goauth.MFALoginKind) goauth.MFALoginKind {
	if kind == "" {
		return goauth.MFALoginKindFactor
	}
	return kind
}
