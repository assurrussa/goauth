package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/oidc"
)

func (s *SessionOIDCState) ReadRefresh(ctx context.Context, raw string) (oidc.SessionRefresh, error) {
	q, err := s.runtime.SQLExecutor(ctx)
	if err != nil {
		return oidc.SessionRefresh{}, err
	}
	return s.readRefresh(ctx, q, raw, false)
}

func (s *SessionOIDCState) LockRefresh(ctx context.Context, raw string) (oidc.SessionRefresh, error) {
	tx, err := s.transaction(ctx)
	if err != nil {
		return oidc.SessionRefresh{}, err
	}
	hint, err := s.readRefresh(ctx, tx, raw, false)
	if err != nil {
		return oidc.SessionRefresh{}, err
	}
	// The family lock always precedes token row locks. Immutable family binding
	// means the unlocked hint cannot redirect the final authoritative lookup.
	if _, err = s.LockFamily(ctx, hint.FamilyID); err != nil {
		return oidc.SessionRefresh{}, err
	}
	return s.readRefresh(ctx, tx, raw, true)
}

func (s *SessionOIDCState) readRefresh(ctx context.Context, q queryRower, raw string, lock bool) (oidc.SessionRefresh, error) {
	selector, err := oidcRefreshSelector(raw)
	if err != nil {
		return oidc.SessionRefresh{}, oidc.ErrRefreshTokenNotFound
	}
	t, err := readOIDCRefreshToken(ctx, q, selector, lock, true)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.SessionRefresh{}, oidc.ErrRefreshTokenNotFound
	}
	if err != nil {
		return oidc.SessionRefresh{}, err
	}
	if !s.runtime.oidcRefreshTokens.matches(raw, t.keyID, t.digest) {
		return oidc.SessionRefresh{}, oidc.ErrRefreshTokenNotFound
	}
	r := oidc.SessionRefresh{
		RefreshToken: t.record(raw), FamilyID: t.familyID, ConsumedAt: nullableTimePointer(t.consumedAt),
		Binding: oidc.SessionBinding{
			SubjectID: t.subjectID.String(), ClientID: t.clientID, SecurityVersion: t.securityVersion,
			SessionID: t.sessionID.String, PolicyStamp: t.policyStamp.String,
			AuthenticatedAt: t.authenticatedAt, AbsoluteExpiresAt: t.absoluteExpiresAt.Time,
		},
	}
	// Strict callers receive token consumption separately from family revocation.
	r.RevokedAt = nullableTimePointer(t.revokedAt)
	if r.RevokedAt == nil {
		r.RevokedAt = nullableTimePointer(t.replayedAt)
	}
	return r, nil
}

func validateSessionRefresh(r oidc.SessionRefresh) error {
	if _, err := validateOIDCRefreshToken(r.RefreshToken); err != nil {
		return err
	}
	if err := validateSessionBinding(r.Binding); err != nil {
		return err
	}
	if _, err := uuid.Parse(r.FamilyID); err != nil {
		return errors.New("invalid OIDC family ID")
	}
	if r.SubjectID != r.Binding.SubjectID || r.ClientID != r.Binding.ClientID || r.SecurityVersion != r.Binding.SecurityVersion ||
		!r.AuthenticatedAt.Equal(r.Binding.AuthenticatedAt) || r.AuthenticatedAt.After(r.CreatedAt) ||
		r.ExpiresAt.After(r.Binding.AbsoluteExpiresAt) || r.ConsumedAt != nil || r.RevokedAt != nil {
		return errors.New("invalid session OIDC refresh token")
	}
	return nil
}

func (s *SessionOIDCState) SaveRefresh(ctx context.Context, r oidc.SessionRefresh) error {
	tx, err := s.transaction(ctx)
	if err != nil {
		return err
	}
	if err = validateSessionRefresh(r); err != nil {
		return err
	}
	if !s.now(ctx).Before(r.ExpiresAt) {
		return oidc.ErrRefreshTokenNotFound
	}
	selector, keyID, digest, err := s.runtime.oidcRefreshTokens.digestActive(r.Token)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO auth_oidc_refresh_families
 (id,subject_id,client_id,scopes,security_version,authenticated_at,created_at,expires_at,
 session_id,authorization_stamp,absolute_expires_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$8)`, r.FamilyID, r.SubjectID, r.ClientID, oidc.ScopeString(r.Scopes),
		r.SecurityVersion, r.AuthenticatedAt, r.CreatedAt, r.Binding.AbsoluteExpiresAt, r.Binding.SessionID, r.Binding.PolicyStamp)
	if err != nil {
		return err
	}
	return insertOIDCRefreshToken(ctx, tx, selector, r.FamilyID, keyID, digest, r.RefreshToken)
}

func (s *SessionOIDCState) LockFamily(ctx context.Context, id string) (oidc.SessionFamily, error) {
	tx, err := s.transaction(ctx)
	if err != nil {
		return oidc.SessionFamily{}, err
	}
	if _, err = uuid.Parse(id); err != nil {
		return oidc.SessionFamily{}, oidc.ErrRefreshTokenNotFound
	}
	var f oidc.SessionFamily
	var scopes string
	var revoked, replayed sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT id,subject_id,client_id,security_version,authenticated_at,
 session_id,authorization_stamp,absolute_expires_at,scopes,revoked_at,replayed_at
 FROM auth_oidc_refresh_families WHERE id=$1 AND session_id IS NOT NULL AND authorization_stamp IS NOT NULL
 AND absolute_expires_at IS NOT NULL FOR UPDATE`, id).Scan(&f.FamilyID, &f.Binding.SubjectID, &f.Binding.ClientID,
		&f.Binding.SecurityVersion, &f.Binding.AuthenticatedAt, &f.Binding.SessionID,
		&f.Binding.PolicyStamp, &f.Binding.AbsoluteExpiresAt,
		&scopes, &revoked, &replayed)
	if errors.Is(err, sql.ErrNoRows) {
		return oidc.SessionFamily{}, oidc.ErrRefreshTokenNotFound
	}
	if err != nil {
		return oidc.SessionFamily{}, err
	}
	f.Scopes = oidc.ParseScope(scopes)
	f.RevokedAt = nullableTimePointer(revoked)
	f.ReplayedAt = nullableTimePointer(replayed)
	return f, nil
}

func (s *SessionOIDCState) RotateRefresh(ctx context.Context, current, next oidc.SessionRefresh, now time.Time) error {
	started := time.Now()
	tx, err := s.transaction(ctx)
	if err != nil {
		return err
	}
	actual, err := s.LockRefresh(ctx, current.Token)
	if err != nil {
		return err
	}
	now = authclock.Now(ctx, now, started)
	if actual.FamilyID != current.FamilyID || !equalSessionBinding(actual.Binding, current.Binding) {
		return oidc.ErrRefreshTokenNotFound
	}
	if actual.ConsumedAt != nil {
		return oidc.ErrRefreshTokenReplay
	}
	if actual.RevokedAt != nil || !now.Before(actual.ExpiresAt) || !now.Before(actual.Binding.AbsoluteExpiresAt) {
		return oidc.ErrRefreshTokenNotFound
	}
	if err = validateSessionRefresh(next); err != nil {
		return err
	}
	if !equalSessionBinding(actual.Binding, next.Binding) || next.FamilyID != actual.FamilyID ||
		oidc.ScopeString(actual.Scopes) != oidc.ScopeString(next.Scopes) || !now.Before(next.ExpiresAt) {
		return errors.New("OIDC rotation changed immutable family metadata or expired")
	}
	selector, _ := oidcRefreshSelector(current.Token)
	nextSelector, keyID, digest, err := s.runtime.oidcRefreshTokens.digestActive(next.Token)
	if err != nil {
		return err
	}
	if nextSelector == selector {
		return errors.New("OIDC rotation requires a new token")
	}
	if err = insertOIDCRefreshToken(ctx, tx, nextSelector, actual.FamilyID, keyID, digest, next.RefreshToken); err != nil {
		return err
	}
	return sessionTransition(tx.ExecContext(ctx, `UPDATE auth_oidc_refresh_tokens SET consumed_at=$2,replaced_by_selector=$3
 WHERE selector=$1 AND consumed_at IS NULL`, selector, now, nextSelector))
}

func (s *SessionOIDCState) RevokeFamily(
	ctx context.Context, id string, reason oidc.SessionRevocationReason, now time.Time,
) error {
	started := time.Now()
	tx, err := s.transaction(ctx)
	if err != nil {
		return err
	}
	if reason != oidc.SessionRevoked && reason != oidc.SessionReplay {
		return errors.New("invalid OIDC family revocation reason")
	}
	f, err := s.LockFamily(ctx, id)
	if err != nil {
		return err
	}
	now = authclock.Now(ctx, now, started)
	if reason == oidc.SessionReplay {
		subjectID, err := goauth.ParseSubjectID(f.Binding.SubjectID)
		if err != nil {
			return err
		}
		t := lockedOIDCRefreshToken{familyID: id, subjectID: subjectID, clientID: f.Binding.ClientID}
		if f.ReplayedAt != nil {
			t.replayedAt = sql.NullTime{Time: *f.ReplayedAt, Valid: true}
		}
		return markOIDCRefreshReplay(ctx, tx, t, now)
	}
	_, err = tx.ExecContext(ctx, `UPDATE auth_oidc_refresh_families SET revoked_at=COALESCE(revoked_at,$2)
 WHERE id=$1 AND session_id IS NOT NULL`, id, now)
	return err
}
