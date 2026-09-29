package postgres

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/assurrussa/goauth"
)

func (s *Store) CreateSession(ctx context.Context, record goauth.SessionRecord) error {
	if record.Session.ID == "" || record.Session.SubjectID.IsZero() || record.FamilyID == "" ||
		record.RefreshSelector == "" || len(record.RefreshDigest.Digest) != 32 {
		return errors.New("invalid session record")
	}

	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return fmt.Errorf("begin session transaction: %w", err)
	}
	defer rollbackWrite(tx, owned)

	if err := lockSubject(ctx, tx, record.Session.SubjectID); err != nil {
		return err
	}
	account, err := getAccount(ctx, tx, record.Session.SubjectID)
	if err != nil {
		return err
	}
	if account.Subject.Status != goauth.SubjectStatusActive {
		return goauth.ErrAccountUnavailable
	}
	if account.Subject.SecurityVersion != record.Session.SecurityVersion {
		return goauth.ErrSecurityVersionMismatch
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_sessions (
    id, subject_id, realm, scope, security_version, created_at, expires_at, revoked_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		record.Session.ID,
		record.Session.SubjectID,
		record.Session.Realm,
		record.Session.Scope,
		record.Session.SecurityVersion,
		record.Session.CreatedAt,
		record.Session.ExpiresAt,
		record.Session.RevokedAt,
	); err != nil {
		return fmt.Errorf("insert auth session: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_refresh_families (
    id, session_id, subject_id, realm, security_version, created_at
)
VALUES ($1, $2, $3, $4, $5, $6)`,
		record.FamilyID,
		record.Session.ID,
		record.Session.SubjectID,
		record.Session.Realm,
		record.Session.SecurityVersion,
		record.Session.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert refresh family: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_refresh_tokens (
    selector, family_id, key_id, secret_digest, created_at, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6)`,
		record.RefreshSelector,
		record.FamilyID,
		record.RefreshDigest.KeyID,
		record.RefreshDigest.Digest,
		record.Session.CreatedAt,
		record.RefreshExpiresAt,
	); err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	if err := finishWrite(tx, owned); err != nil {
		return fmt.Errorf("commit session transaction: %w", err)
	}

	return nil
}

func (s *Store) PeekRefresh(ctx context.Context, request goauth.RefreshRotationRequest) (goauth.RefreshRotationResult, error) {
	return s.rotateRefresh(ctx, request, true)
}

func (s *Store) RotateRefresh(ctx context.Context, request goauth.RefreshRotationRequest) (goauth.RefreshRotationResult, error) {
	return s.rotateRefresh(ctx, request, false)
}

func (s *Store) rotateRefresh(
	ctx context.Context,
	request goauth.RefreshRotationRequest,
	peek bool,
) (goauth.RefreshRotationResult, error) {
	if request.CurrentSelector == "" || len(request.CurrentDigest.Digest) != 32 {
		return goauth.RefreshRotationResult{Status: goauth.RefreshRotationInvalid}, nil
	}
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.RefreshRotationResult{}, fmt.Errorf("begin refresh rotation: %w", err)
	}
	defer rollbackWrite(tx, owned)

	// Serialize every security mutation on the canonical subject before children.
	if err := lockRefreshSubject(ctx, tx, request.CurrentSelector); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return goauth.RefreshRotationResult{Status: goauth.RefreshRotationInvalid}, nil
		}
		return goauth.RefreshRotationResult{}, err
	}

	var (
		storedKeyID      string
		storedDigest     []byte
		tokenExpiresAt   time.Time
		tokenConsumedAt  sql.NullTime
		familyID         string
		familyRevokedAt  sql.NullTime
		familyReplayedAt sql.NullTime
		session          goauth.Session
		sessionRealm     string
		sessionScope     string
		sessionRevokedAt sql.NullTime
		subjectStatus    string
		subjectVersion   int64
	)
	err = tx.QueryRowContext(ctx, `
SELECT
    rt.key_id,
    rt.secret_digest,
    rt.expires_at,
    rt.consumed_at,
    f.id,
    f.revoked_at,
    f.replayed_at,
    sess.id,
    sess.subject_id,
    sess.realm,
    sess.scope,
    sess.security_version,
    sess.created_at,
    sess.expires_at,
    sess.revoked_at,
    sub.status,
    sub.security_version
FROM auth_refresh_tokens rt
JOIN auth_refresh_families f ON f.id = rt.family_id
JOIN auth_sessions sess ON sess.id = f.session_id
JOIN auth_subjects sub ON sub.id = f.subject_id
WHERE rt.selector = $1
FOR UPDATE OF rt, f, sess, sub`, request.CurrentSelector).Scan(
		&storedKeyID,
		&storedDigest,
		&tokenExpiresAt,
		&tokenConsumedAt,
		&familyID,
		&familyRevokedAt,
		&familyReplayedAt,
		&session.ID,
		&session.SubjectID,
		&sessionRealm,
		&sessionScope,
		&session.SecurityVersion,
		&session.CreatedAt,
		&session.ExpiresAt,
		&sessionRevokedAt,
		&subjectStatus,
		&subjectVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.RefreshRotationResult{Status: goauth.RefreshRotationInvalid}, nil
	}
	if err != nil {
		return goauth.RefreshRotationResult{}, fmt.Errorf("lock refresh token: %w", err)
	}
	session.Realm = goauth.Realm(sessionRealm)
	session.Scope = goauth.SessionScope(sessionScope)
	if sessionRevokedAt.Valid {
		value := sessionRevokedAt.Time
		session.RevokedAt = &value
	}
	account, err := getAccount(ctx, tx, session.SubjectID)
	if err != nil {
		return goauth.RefreshRotationResult{}, err
	}
	result := goauth.RefreshRotationResult{Account: account, Session: session, FamilyID: familyID}

	if storedKeyID != request.CurrentDigest.KeyID || !hmac.Equal(storedDigest, request.CurrentDigest.Digest) {
		result.Status = goauth.RefreshRotationInvalid
		return result, nil
	}
	if tokenConsumedAt.Valid {
		if peek {
			result.Status = goauth.RefreshRotationReplayed
			return result, nil
		}
		return revokeRefreshReplay(ctx, tx, owned, result, request.Now)
	}
	if !request.Now.Before(tokenExpiresAt) || !request.Now.Before(session.ExpiresAt) {
		result.Status = goauth.RefreshRotationExpired
		return result, nil
	}
	if familyRevokedAt.Valid || familyReplayedAt.Valid || sessionRevokedAt.Valid ||
		goauth.SubjectStatus(subjectStatus) != goauth.SubjectStatusActive ||
		subjectVersion != session.SecurityVersion {
		result.Status = goauth.RefreshRotationRevoked
		return result, nil
	}

	if !refreshSnapshotMatches(request, account) {
		result.Status = goauth.RefreshRotationRevoked
		return result, nil
	}
	if peek {
		result.Status = goauth.RefreshRotationSucceeded
		return result, nil
	}
	if request.NextSelector == "" || len(request.NextDigest.Digest) != 32 {
		result.Status = goauth.RefreshRotationInvalid
		return result, nil
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_refresh_tokens (
    selector, family_id, key_id, secret_digest, created_at, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6)`,
		request.NextSelector,
		familyID,
		request.NextDigest.KeyID,
		request.NextDigest.Digest,
		request.Now,
		request.NextExpiresAt,
	); err != nil {
		return goauth.RefreshRotationResult{}, fmt.Errorf("insert rotated refresh token: %w", err)
	}
	update, err := tx.ExecContext(ctx, `
UPDATE auth_refresh_tokens
SET consumed_at = $2, replaced_by_selector = $3
WHERE selector = $1 AND consumed_at IS NULL`,
		request.CurrentSelector,
		request.Now,
		request.NextSelector,
	)
	if err != nil {
		return goauth.RefreshRotationResult{}, fmt.Errorf("consume current refresh token: %w", err)
	}
	rows, err := update.RowsAffected()
	if err != nil {
		return goauth.RefreshRotationResult{}, fmt.Errorf("read refresh consume count: %w", err)
	}
	if rows != 1 {
		return goauth.RefreshRotationResult{}, errors.New("refresh consume guard did not update exactly one row")
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.RefreshRotationResult{}, fmt.Errorf("commit refresh rotation: %w", err)
	}
	result.Status = goauth.RefreshRotationSucceeded
	return result, nil
}

func (s *Store) IntrospectSession(ctx context.Context, sessionID string) (goauth.SessionSecurity, error) {
	var (
		result    goauth.SessionSecurity
		realm     string
		scope     string
		status    string
		revokedAt sql.NullTime
	)
	err := s.queryer(ctx).QueryRowContext(ctx, `
SELECT
    sess.id,
    sess.subject_id,
    sess.realm,
    sess.scope,
    sess.security_version,
    sess.created_at,
    sess.expires_at,
    sess.revoked_at,
    sub.status,
    sub.security_version
FROM auth_sessions sess
JOIN auth_subjects sub ON sub.id = sess.subject_id
WHERE sess.id = $1`, sessionID).Scan(
		&result.Session.ID,
		&result.Session.SubjectID,
		&realm,
		&scope,
		&result.Session.SecurityVersion,
		&result.Session.CreatedAt,
		&result.Session.ExpiresAt,
		&revokedAt,
		&status,
		&result.CurrentVersion,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.SessionSecurity{}, goauth.ErrSessionRevoked
	}
	if err != nil {
		return goauth.SessionSecurity{}, fmt.Errorf("introspect auth session: %w", err)
	}
	result.Session.Realm = goauth.Realm(realm)
	result.Session.Scope = goauth.SessionScope(scope)
	result.SubjectStatus = goauth.SubjectStatus(status)
	if revokedAt.Valid {
		value := revokedAt.Time
		result.Session.RevokedAt = &value
	}

	return result, nil
}

func (s *Store) RevokeSession(
	ctx context.Context,
	subjectID goauth.SubjectID,
	sessionID string,
	now time.Time,
) (bool, error) {
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return false, fmt.Errorf("begin session revocation: %w", err)
	}
	defer rollbackWrite(tx, owned)
	if err := lockSubject(ctx, tx, subjectID); err != nil {
		return false, err
	}

	result, err := tx.ExecContext(ctx, `
UPDATE auth_sessions
SET revoked_at = $3
WHERE id = $1 AND subject_id = $2 AND revoked_at IS NULL`, sessionID, subjectID, now)
	if err != nil {
		return false, fmt.Errorf("revoke auth session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read session revocation count: %w", err)
	}
	if rows == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_refresh_families
SET revoked_at = COALESCE(revoked_at, $2)
WHERE session_id = $1`, sessionID, now); err != nil {
		return false, fmt.Errorf("revoke session refresh families: %w", err)
	}
	if err := finishWrite(tx, owned); err != nil {
		return false, fmt.Errorf("commit session revocation: %w", err)
	}

	return true, nil
}

func (s *Store) RevokeSubjectSessions(
	ctx context.Context,
	subjectID goauth.SubjectID,
	now time.Time,
) (int64, error) {
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin subject session revocation: %w", err)
	}
	defer rollbackWrite(tx, owned)
	if err := lockSubject(ctx, tx, subjectID); err != nil {
		if errors.Is(err, goauth.ErrAccountNotFound) {
			return 0, nil
		}
		return 0, err
	}

	if _, err := tx.ExecContext(ctx, `UPDATE auth_subjects
SET security_version=security_version+1,updated_at=$2 WHERE id=$1`, subjectID, now); err != nil {
		return 0, err
	}

	revoked, err := revokeSubjectSecurityState(ctx, tx, subjectID, now)
	if err != nil {
		return 0, err
	}
	if err := finishWrite(tx, owned); err != nil {
		return 0, fmt.Errorf("commit subject session revocation: %w", err)
	}

	return revoked, nil
}

func revokeSubjectSecurityState(
	ctx context.Context,
	tx *sql.Tx,
	subjectID goauth.SubjectID,
	now time.Time,
) (int64, error) {
	result, err := tx.ExecContext(ctx, `
UPDATE auth_sessions
SET revoked_at = $2
WHERE subject_id = $1 AND revoked_at IS NULL`, subjectID, now)
	if err != nil {
		return 0, fmt.Errorf("revoke subject sessions: %w", err)
	}

	revoked, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read subject session revocation count: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_refresh_families
SET revoked_at = COALESCE(revoked_at, $2)
WHERE subject_id = $1`, subjectID, now); err != nil {
		return 0, fmt.Errorf("revoke subject refresh families: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_oidc_refresh_families
SET revoked_at = COALESCE(revoked_at, $2)
WHERE subject_id = $1`, subjectID, now); err != nil {
		return 0, fmt.Errorf("revoke subject OIDC refresh families: %w", err)
	}
	if err := invalidateEmailSecurityState(ctx, tx, subjectID, now); err != nil {
		return 0, err
	}

	return revoked, nil
}

func (s *Store) SetSubjectStatus(
	ctx context.Context,
	subjectID goauth.SubjectID,
	status goauth.SubjectStatus,
	now time.Time,
) (goauth.Subject, error) {
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return goauth.Subject{}, fmt.Errorf("begin subject status transaction: %w", err)
	}
	defer rollbackWrite(tx, owned)

	var subject goauth.Subject
	var storedStatus string
	err = tx.QueryRowContext(ctx, `
SELECT id, status, security_version, created_at, updated_at
FROM auth_subjects
WHERE id = $1
FOR UPDATE`, subjectID).Scan(
		&subject.ID,
		&storedStatus,
		&subject.SecurityVersion,
		&subject.CreatedAt,
		&subject.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.Subject{}, goauth.ErrAccountNotFound
	}
	if err != nil {
		return goauth.Subject{}, fmt.Errorf("lock auth subject: %w", err)
	}
	subject.Status = goauth.SubjectStatus(storedStatus)
	if subject.Status == status {
		if err := finishWrite(tx, owned); err != nil {
			return goauth.Subject{}, fmt.Errorf("commit unchanged subject status: %w", err)
		}
		return subject, nil
	}
	if err := tx.QueryRowContext(ctx, `
UPDATE auth_subjects
SET status = $2, security_version = security_version + 1, updated_at = $3
WHERE id = $1
RETURNING id, status, security_version, created_at, updated_at`,
		subjectID,
		status,
		now,
	).Scan(
		&subject.ID,
		&storedStatus,
		&subject.SecurityVersion,
		&subject.CreatedAt,
		&subject.UpdatedAt,
	); err != nil {
		return goauth.Subject{}, fmt.Errorf("update auth subject status: %w", err)
	}
	subject.Status = goauth.SubjectStatus(storedStatus)
	if _, err := revokeSubjectSecurityState(ctx, tx, subjectID, now); err != nil {
		return goauth.Subject{}, err
	}
	if err := invalidatePasswordResets(ctx, tx, subjectID, now); err != nil {
		return goauth.Subject{}, err
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.Subject{}, fmt.Errorf("commit subject status transaction: %w", err)
	}

	return subject, nil
}

func lockSubject(ctx context.Context, tx *sql.Tx, id goauth.SubjectID) error {
	var found goauth.SubjectID
	err := tx.QueryRowContext(ctx, `SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE`, id).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.ErrAccountNotFound
	}
	return err
}

func lockRefreshSubject(ctx context.Context, tx *sql.Tx, selector string) error {
	var id goauth.SubjectID
	err := tx.QueryRowContext(ctx, `SELECT f.subject_id FROM auth_refresh_tokens t
 JOIN auth_refresh_families f ON f.id=t.family_id WHERE t.selector=$1`, selector).Scan(&id)
	if err != nil {
		return err
	}
	return lockSubject(ctx, tx, id)
}

func revokeRefreshReplay(
	ctx context.Context, tx *sql.Tx, owned bool, result goauth.RefreshRotationResult, now time.Time,
) (goauth.RefreshRotationResult, error) {
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_refresh_families
SET revoked_at = COALESCE(revoked_at, $2), replayed_at = COALESCE(replayed_at, $2)
WHERE id = $1`, result.FamilyID, now); err != nil {
		return goauth.RefreshRotationResult{}, fmt.Errorf("revoke replayed refresh family: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1`,
		result.Session.ID,
		now,
	); err != nil {
		return goauth.RefreshRotationResult{}, fmt.Errorf("revoke replayed session: %w", err)
	}
	if err := finishWrite(tx, owned); err != nil {
		return goauth.RefreshRotationResult{}, fmt.Errorf("commit refresh replay revocation: %w", err)
	}
	result.Status = goauth.RefreshRotationReplayed
	return result, nil
}

func refreshSnapshotMatches(request goauth.RefreshRotationRequest, account goauth.Account) bool {
	return request.ExpectedSecurityVersion == 0 ||
		(account.Subject.SecurityVersion == request.ExpectedSecurityVersion &&
			account.PrimaryEmail.NormalizedValue == request.ExpectedNormalizedEmail &&
			account.EmailVerified() == request.ExpectedEmailVerified)
}
