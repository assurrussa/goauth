package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/assurrussa/goauth"
)

func (s *Store) EnsureMFAFactor(ctx context.Context, subject goauth.SubjectID) (goauth.MFAFactorRecord, error) {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return goauth.MFAFactorRecord{}, err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return goauth.MFAFactorRecord{}, err
	}
	id, err := goauth.NewMFALoginID()
	if err != nil {
		return goauth.MFAFactorRecord{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO auth_mfa_factors(subject_id,factor_id,revision)
 VALUES($1,$2,1) ON CONFLICT(subject_id) DO NOTHING`, subject, id)
	if err != nil {
		return goauth.MFAFactorRecord{}, err
	}
	return s.LockMFAFactor(ctx, subject)
}

func (s *Store) SaveMFAEnrollment(ctx context.Context, e goauth.MFAEnrollmentRecord) error {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return err
	}
	if err := lockActiveSubject(ctx, tx, e.SubjectID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO auth_mfa_enrollments
 (subject_id,id,revision,security_version,session_id,binding,key_id,secret,created_at,expires_at)
 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10 FROM auth_subjects a
 JOIN auth_mfa_factors f ON f.subject_id=a.id JOIN auth_sessions s ON s.subject_id=a.id
 WHERE a.id=$1 AND a.security_version=$4 AND a.status='active' AND f.revision=$3
 AND s.id=$5 AND s.security_version=$4 AND s.scope='authenticated'
 AND s.revoked_at IS NULL AND s.expires_at>$9
 ON CONFLICT(subject_id) DO UPDATE SET id=EXCLUDED.id,revision=EXCLUDED.revision,
 security_version=EXCLUDED.security_version,session_id=EXCLUDED.session_id,binding=EXCLUDED.binding,
 key_id=EXCLUDED.key_id,secret=EXCLUDED.secret,created_at=EXCLUDED.created_at,expires_at=EXCLUDED.expires_at`,
		e.SubjectID, e.ID, e.Revision, e.SecurityVersion, e.SessionID, e.Binding[:], e.KeyID, e.Ciphertext, e.CreatedAt, e.ExpiresAt)
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

func (s *Store) LockMFAEnrollment(ctx context.Context, subject goauth.SubjectID) (goauth.MFAEnrollmentRecord, error) {
	var e goauth.MFAEnrollmentRecord
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return e, err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return e, err
	}
	var binding []byte
	err = tx.QueryRowContext(ctx,
		`SELECT subject_id,id,revision,security_version,session_id,binding,key_id,secret,created_at,expires_at
 FROM auth_mfa_enrollments WHERE subject_id=$1 FOR UPDATE`, subject).
		Scan(&e.SubjectID, &e.ID, &e.Revision, &e.SecurityVersion, &e.SessionID, &binding, &e.KeyID, &e.Ciphertext,
			&e.CreatedAt, &e.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.MFAEnrollmentRecord{}, goauth.ErrMFALoginDenied
	}
	if err != nil {
		return goauth.MFAEnrollmentRecord{}, err
	}
	if len(binding) != len(e.Binding) {
		return goauth.MFAEnrollmentRecord{}, goauth.ErrMFALoginDenied
	}
	copy(e.Binding[:], binding)
	return e, nil
}

func (s *Store) ReplaceMFAFactor(ctx context.Context, subject goauth.SubjectID, expected,
	next goauth.MFAFactorRecord,
) (bool, error) {
	if next.Revision != expected.Revision+1 || next.ID == "" || next.Revision < 1 {
		return false, goauth.ErrMFALoginDenied
	}
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return false, err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth_mfa_factors SET factor_id=$4,revision=$5,
 enabled=$6,key_id=$7,secret=COALESCE($8,''::bytea),last_step=$9
 WHERE subject_id=$1 AND factor_id=$2 AND revision=$3 AND last_step=$10 AND enabled=$11`,
		subject, expected.ID, expected.Revision, next.ID, next.Revision, next.Enabled, next.KeyID, next.Ciphertext,
		next.LastStep, expected.LastStep, expected.Enabled)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (s *Store) ReplaceMFARecovery(ctx context.Context, subject goauth.SubjectID, digests [][]byte) error {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_mfa_recovery WHERE subject_id=$1`, subject); err != nil {
		return err
	}
	for _, digest := range digests {
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_mfa_recovery(subject_id,digest) VALUES($1,$2)`, subject,
			digest); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CancelMFAEnrollment(ctx context.Context, subject goauth.SubjectID, session string, binding [32]byte) error {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx,
		`DELETE FROM auth_mfa_enrollments WHERE subject_id=$1 AND session_id=$2 AND binding=$3`, subject, session, binding[:])
	return err
}

func (s *Store) InvalidateMFAState(ctx context.Context, subject goauth.SubjectID) error {
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return err
	}
	if err := lockActiveSubject(ctx, tx, subject); err != nil {
		return err
	}
	for _, query := range []string{
		`DELETE FROM auth_mfa_pending WHERE subject_id=$1`,
		`DELETE FROM auth_mfa_enrollments WHERE subject_id=$1`,
	} {
		if _, err := tx.ExecContext(ctx, query, subject); err != nil {
			return err
		}
	}
	return nil
}
