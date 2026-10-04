package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/assurrussa/goauth/oidc"
)

const requestDigestPurpose = "oidc-authorization-request"

func (s *SessionOIDCState) SaveRequest(ctx context.Context, record oidc.SessionRequest) error {
	tx, err := s.transaction(ctx)
	if err != nil {
		return err
	}
	if record.ClientID == "" || record.ClientRevision < 1 || record.RedirectURI == "" ||
		record.BrowserBinding == "" || len(record.BrowserBinding) > 256 || record.CodeChallenge == "" ||
		record.CodeChallengeMethod != "S256" || record.RequestedAt.IsZero() || !record.ExpiresAt.After(record.RequestedAt) ||
		record.ExpiresAt.Sub(record.RequestedAt) > 10*time.Minute || !s.now(ctx).Before(record.ExpiresAt) ||
		record.ConsumedAt != nil || record.LoginCompletion != nil || (record.MaxAgeSeconds != nil && *record.MaxAgeSeconds < 0) {
		return errors.New("invalid OIDC authorization request")
	}
	selector, keyID, digest, err := s.digest(requestDigestPurpose, record.Challenge)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO auth_oidc_authorization_requests
 (selector,key_id,secret_digest,client_id,client_revision,redirect_uri,state,nonce,scopes,
 code_challenge,code_challenge_method,requested_at,expires_at,prompt,max_age_seconds,browser_binding)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		selector, keyID, digest, record.ClientID, record.ClientRevision, record.RedirectURI, record.State, record.Nonce,
		oidc.ScopeString(record.Scopes), record.CodeChallenge, record.CodeChallengeMethod, record.RequestedAt,
		record.ExpiresAt, strings.Join(record.Prompt, " "), record.MaxAgeSeconds, record.BrowserBinding)
	return err
}

func (s *SessionOIDCState) ReadRequest(ctx context.Context, challenge string) (oidc.SessionRequest, error) {
	q, err := s.runtime.SQLExecutor(ctx)
	if err != nil {
		return oidc.SessionRequest{}, err
	}
	return s.readRequest(ctx, q, challenge, false)
}

func (s *SessionOIDCState) readRequest(ctx context.Context, q queryRower, raw string, lock bool) (oidc.SessionRequest, error) {
	selector, err := oidcRefreshSelector(raw)
	if err != nil {
		return oidc.SessionRequest{}, oidc.ErrAuthorizationRequestNotFound
	}
	query := `SELECT key_id,secret_digest,client_id,client_revision,redirect_uri,state,nonce,scopes,
 code_challenge,code_challenge_method,requested_at,expires_at,prompt,max_age_seconds,browser_binding,
 login_session_id,login_cookie_digest,login_authenticated_at,consumed_at
 FROM auth_oidc_authorization_requests WHERE selector=$1`
	if lock {
		query += sessionOIDCForUpdate
	}
	var r oidc.SessionRequest
	var keyID, scopes, prompt string
	var digest []byte
	var age sql.NullInt64
	var sid, cookie sql.NullString
	var authenticated, consumed sql.NullTime
	err = q.QueryRowContext(ctx, query, selector).Scan(&keyID, &digest, &r.ClientID, &r.ClientRevision, &r.RedirectURI,
		&r.State, &r.Nonce, &scopes, &r.CodeChallenge, &r.CodeChallengeMethod, &r.RequestedAt, &r.ExpiresAt,
		&prompt, &age, &r.BrowserBinding, &sid, &cookie, &authenticated, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.SessionRequest{}, oidc.ErrAuthorizationRequestNotFound
	}
	if err != nil {
		return oidc.SessionRequest{}, err
	}
	if !s.matches(requestDigestPurpose, raw, keyID, digest) {
		return oidc.SessionRequest{}, oidc.ErrAuthorizationRequestNotFound
	}
	r.Challenge = raw
	r.Scopes = oidc.ParseScope(scopes)
	r.Prompt = strings.Fields(prompt)
	if age.Valid {
		r.MaxAgeSeconds = &age.Int64
	}
	if sid.Valid && cookie.Valid && authenticated.Valid {
		r.LoginCompletion = &oidc.RequestLoginCompletion{
			SessionID: sid.String, CookieDigest: cookie.String, AuthenticatedAt: authenticated.Time,
		}
	}
	r.ConsumedAt = nullableTimePointer(consumed)
	return r, nil
}

func (s *SessionOIDCState) MarkLoginComplete(
	ctx context.Context, challenge, browserBinding string, completion oidc.RequestLoginCompletion,
) error {
	tx, err := s.transaction(ctx)
	if err != nil {
		return err
	}
	if completion.SessionID == "" || len(completion.SessionID) > 256 || completion.CookieDigest == "" ||
		len(completion.CookieDigest) > 256 || completion.AuthenticatedAt.IsZero() {
		return errors.New("invalid OIDC login completion")
	}
	r, err := s.readRequest(ctx, tx, challenge, true)
	if err != nil {
		return err
	}
	now := s.now(ctx)
	if r.ConsumedAt != nil || r.LoginCompletion != nil || r.BrowserBinding != browserBinding ||
		!now.Before(r.ExpiresAt) || completion.AuthenticatedAt.After(now) || completion.AuthenticatedAt.Before(r.RequestedAt) {
		return oidc.ErrSessionStateConflict
	}
	selector, _ := oidcRefreshSelector(challenge)
	return sessionTransition(tx.ExecContext(ctx, `UPDATE auth_oidc_authorization_requests
 SET login_session_id=$2,login_cookie_digest=$3,login_authenticated_at=$4
 WHERE selector=$1 AND consumed_at IS NULL AND login_session_id IS NULL AND expires_at>$5 AND browser_binding=$6`,
		selector, completion.SessionID, completion.CookieDigest, completion.AuthenticatedAt, now, browserBinding))
}

func (s *SessionOIDCState) ConsumeRequest(ctx context.Context, challenge string) (oidc.SessionRequest, error) {
	tx, err := s.transaction(ctx)
	if err != nil {
		return oidc.SessionRequest{}, err
	}
	r, err := s.readRequest(ctx, tx, challenge, true)
	if err != nil {
		return oidc.SessionRequest{}, err
	}
	now := s.now(ctx)
	if r.ConsumedAt != nil || r.LoginCompletion == nil || !now.Before(r.ExpiresAt) {
		return oidc.SessionRequest{}, oidc.ErrSessionStateConflict
	}
	selector, _ := oidcRefreshSelector(challenge)
	err = sessionTransition(tx.ExecContext(ctx, `UPDATE auth_oidc_authorization_requests SET consumed_at=$2
 WHERE selector=$1 AND consumed_at IS NULL AND expires_at>$2`, selector, now))
	if err != nil {
		return oidc.SessionRequest{}, err
	}
	return r, nil
}
