package postgres

import (
	"context"

	"github.com/assurrussa/goauth"
)

func (s *Store) SaveMFALoginSetup(ctx context.Context, p goauth.MFALoginPending, setup goauth.MFALoginSetup) error {
	if p.Kind != goauth.MFALoginKindEnrollment || len(setup.RecoveryDigests) != 10 {
		return goauth.ErrMFALoginDenied
	}
	recovery := make([]byte, 0, 320)
	for _, digest := range setup.RecoveryDigests {
		if len(digest) != 32 {
			return goauth.ErrMFALoginDenied
		}
		recovery = append(recovery, digest...)
	}
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return err
	}
	if err := lockActiveSubject(ctx, tx, p.SubjectID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth_mfa_pending SET setup_id=$10,setup_key_id=$11,setup_secret=$12,setup_recovery=$13
 WHERE id=$1 AND subject_id=$2 AND realm=$3 AND security_version=$4 AND factor_id=$5 AND factor_revision=$6
 AND binding=$7 AND authenticated_at=$8 AND expires_at=$9 AND kind='enrollment'
 AND expires_at>clock_timestamp() AND setup_id=$14`, p.ID, p.SubjectID, p.Realm, p.SecurityVersion, p.FactorID,
		p.FactorRevision, p.BindingDigest[:], p.AuthenticatedAt, p.ExpiresAt,
		setup.ID, setup.KeyID, setup.Ciphertext, recovery, p.Setup.ID)
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

// MarkMFASessionAdmission is called only after creating the session in the same
// transaction. Runtime callers never upgrade an existing session's provenance.
func (s *Store) MarkMFASessionAdmission(ctx context.Context, session goauth.Session, admission goauth.MFASessionAdmission) error {
	if admission != goauth.MFASessionAdmissionFactor && admission != goauth.MFASessionAdmissionExternal {
		return goauth.ErrMFALoginDenied
	}
	tx, err := s.mfaTx(ctx)
	if err != nil {
		return err
	}
	if err := lockActiveSubject(ctx, tx, session.SubjectID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET mfa_admission=$5
 WHERE id=$1 AND subject_id=$2 AND realm=$3 AND security_version=$4
 AND mfa_admission='unknown' AND revoked_at IS NULL AND expires_at>clock_timestamp()
 AND ($5='external' OR EXISTS(SELECT 1 FROM auth_mfa_factors WHERE subject_id=$2 AND enabled))`,
		session.ID, session.SubjectID, session.Realm, session.SecurityVersion, admission)
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

func (s *Store) AdmitRequiredMFASession(ctx context.Context, session goauth.Session) error {
	ex := s.queryer(ctx)
	var admitted bool
	err := ex.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM auth_sessions s JOIN auth_subjects a ON a.id=s.subject_id
 WHERE s.id=$1 AND s.subject_id=$2 AND s.realm=$3 AND s.scope=$4 AND s.security_version=$5
 AND a.security_version=$5 AND a.status='active' AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
 AND (s.mfa_admission='external' OR (s.mfa_admission='factor'
 AND EXISTS(SELECT 1 FROM auth_mfa_factors f WHERE f.subject_id=s.subject_id AND f.enabled))))`,
		session.ID, session.SubjectID, session.Realm, session.Scope, session.SecurityVersion).Scan(&admitted)
	if err != nil {
		return err
	}
	if !admitted {
		return goauth.ErrMFARequired
	}
	return nil
}

func scanMFALoginSetup(setup *goauth.MFALoginSetup, recovery []byte) error {
	if len(recovery) == 0 && setup.ID == "" {
		return nil
	}
	if len(recovery) != 320 {
		return goauth.ErrMFALoginDenied
	}
	setup.RecoveryDigests = make([][]byte, 10)
	for i := range setup.RecoveryDigests {
		setup.RecoveryDigests[i] = append([]byte(nil), recovery[i*32:(i+1)*32]...)
	}
	return nil
}

var _ goauth.MFARequiredStore = (*Store)(nil)
