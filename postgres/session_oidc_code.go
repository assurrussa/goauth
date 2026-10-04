package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/oidc"
)

const codeDigestPurpose = "oidc-authorization-code"

func (s *SessionOIDCState) SaveCode(ctx context.Context, r oidc.SessionCode) error {
	tx, err := s.transaction(ctx)
	if err != nil {
		return err
	}
	if err = validateSessionBinding(r.Binding); err != nil {
		return err
	}
	if r.SubjectID != r.Binding.SubjectID || r.ClientID != r.Binding.ClientID || r.SecurityVersion != r.Binding.SecurityVersion ||
		!r.AuthenticatedAt.Equal(r.Binding.AuthenticatedAt) || r.RedirectURI == "" ||
		r.CodeChallenge == "" || r.CodeChallengeMethod != "S256" ||
		r.CreatedAt.IsZero() || r.AuthenticatedAt.After(r.CreatedAt) || !r.ExpiresAt.After(r.CreatedAt) ||
		r.ExpiresAt.Sub(r.CreatedAt) > time.Minute || r.ExpiresAt.After(r.Binding.AbsoluteExpiresAt) ||
		!s.now(ctx).Before(r.ExpiresAt) || r.ConsumedAt != nil || r.FamilyID != "" {
		return errors.New("invalid OIDC authorization code")
	}
	selector, keyID, digest, err := s.digest(codeDigestPurpose, r.Code)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO auth_oidc_authorization_codes
 (selector,key_id,secret_digest,subject_id,security_version,client_id,redirect_uri,scopes,nonce,
 code_challenge,code_challenge_method,authenticated_at,created_at,expires_at,session_id,authorization_stamp,absolute_expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		selector, keyID, digest, r.SubjectID, r.SecurityVersion, r.ClientID, r.RedirectURI, oidc.ScopeString(r.Scopes), r.Nonce,
		r.CodeChallenge, r.CodeChallengeMethod, r.AuthenticatedAt, r.CreatedAt, r.ExpiresAt,
		r.Binding.SessionID, r.Binding.PolicyStamp, r.Binding.AbsoluteExpiresAt)
	return err
}

func (s *SessionOIDCState) ReadCode(ctx context.Context, raw string) (oidc.SessionCode, error) {
	q, err := s.runtime.SQLExecutor(ctx)
	if err != nil {
		return oidc.SessionCode{}, err
	}
	return s.readCode(ctx, q, raw, false)
}

func (s *SessionOIDCState) LockCode(ctx context.Context, raw string) (oidc.SessionCode, error) {
	tx, err := s.transaction(ctx)
	if err != nil {
		return oidc.SessionCode{}, err
	}
	return s.readCode(ctx, tx, raw, true)
}

func (s *SessionOIDCState) readCode(ctx context.Context, q queryRower, raw string, lock bool) (oidc.SessionCode, error) {
	selector, err := oidcRefreshSelector(raw)
	if err != nil {
		return oidc.SessionCode{}, oidc.ErrAuthorizationCodeNotFound
	}
	query := `SELECT key_id,secret_digest,subject_id,security_version,client_id,redirect_uri,scopes,nonce,
 code_challenge,code_challenge_method,authenticated_at,created_at,expires_at,
 session_id,authorization_stamp,absolute_expires_at,consumed_at,family_id
 FROM auth_oidc_authorization_codes WHERE selector=$1`
	if lock {
		query += sessionOIDCForUpdate
	}
	var r oidc.SessionCode
	var keyID, scopes string
	var digest []byte
	var consumed sql.NullTime
	var family sql.NullString
	err = q.QueryRowContext(ctx, query, selector).Scan(&keyID, &digest, &r.SubjectID, &r.SecurityVersion, &r.ClientID,
		&r.RedirectURI, &scopes, &r.Nonce, &r.CodeChallenge, &r.CodeChallengeMethod, &r.AuthenticatedAt, &r.CreatedAt, &r.ExpiresAt,
		&r.Binding.SessionID, &r.Binding.PolicyStamp, &r.Binding.AbsoluteExpiresAt, &consumed, &family)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.SessionCode{}, oidc.ErrAuthorizationCodeNotFound
	}
	if err != nil {
		return oidc.SessionCode{}, err
	}
	if !s.matches(codeDigestPurpose, raw, keyID, digest) {
		return oidc.SessionCode{}, oidc.ErrAuthorizationCodeNotFound
	}
	r.Code = raw
	r.Scopes = oidc.ParseScope(scopes)
	r.ConsumedAt = nullableTimePointer(consumed)
	r.FamilyID = family.String
	r.Binding.SubjectID = r.SubjectID
	r.Binding.ClientID = r.ClientID
	r.Binding.SecurityVersion = r.SecurityVersion
	r.Binding.AuthenticatedAt = r.AuthenticatedAt
	return r, nil
}

func (s *SessionOIDCState) ConsumeCode(ctx context.Context, raw, familyID string, now time.Time) (oidc.SessionCode, error) {
	started := time.Now()
	tx, err := s.transaction(ctx)
	if err != nil {
		return oidc.SessionCode{}, err
	}
	r, err := s.readCode(ctx, tx, raw, true)
	if err != nil {
		return oidc.SessionCode{}, err
	}
	now = authclock.Now(ctx, now, started)
	if r.ConsumedAt != nil {
		return oidc.SessionCode{}, oidc.ErrSessionStateConflict
	}
	// An owner may burn a denied or expired code. Linking a successful family
	// additionally requires a still-live code and its immutable family binding.
	if familyID != "" && !now.Before(r.ExpiresAt) {
		return oidc.SessionCode{}, oidc.ErrSessionStateConflict
	}
	var family any
	if familyID != "" {
		family = familyID
	}
	selector, _ := oidcRefreshSelector(raw)
	err = sessionTransition(tx.ExecContext(ctx, `UPDATE auth_oidc_authorization_codes SET consumed_at=$2,family_id=$3
 WHERE selector=$1 AND consumed_at IS NULL`, selector, now, family))
	if err != nil {
		return oidc.SessionCode{}, err
	}
	r.ConsumedAt = &now
	r.FamilyID = familyID
	return r, nil
}
