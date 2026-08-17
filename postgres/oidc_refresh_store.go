package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
)

const maxOIDCRefreshTokenLength = 4096

// OIDCRefreshTokenStore persists only a deterministic selector and an HMAC
// digest. The raw bearer token exists only at the provider boundary.
type OIDCRefreshTokenStore struct {
	db   *sql.DB
	keys goauth.KeyRing
}

func NewOIDCRefreshTokenStore(db *sql.DB, keys goauth.KeyRing) (*OIDCRefreshTokenStore, error) {
	if db == nil {
		return nil, errors.New("PostgreSQL database is required")
	}
	if _, err := keys.Active(); err != nil {
		return nil, fmt.Errorf("validate OIDC refresh token keys: %w", err)
	}

	return &OIDCRefreshTokenStore{db: db, keys: keys}, nil
}

func (s *OIDCRefreshTokenStore) Save(ctx context.Context, token oidc.RefreshToken) error {
	subjectID, err := validateOIDCRefreshToken(token)
	if err != nil {
		return err
	}
	selector, keyID, digest, err := s.digestActive(token.Token)
	if err != nil {
		return err
	}
	familyID := uuid.NewString()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin OIDC refresh token issue: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_oidc_refresh_families (
    id, subject_id, client_id, scopes, security_version,
    authenticated_at, created_at, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		familyID,
		subjectID,
		token.ClientID,
		oidc.ScopeString(token.Scopes),
		token.SecurityVersion,
		token.AuthenticatedAt,
		token.CreatedAt,
		token.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert OIDC refresh family: %w", err)
	}
	if err := insertOIDCRefreshToken(ctx, tx, selector, familyID, keyID, digest, token); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit OIDC refresh token issue: %w", err)
	}

	return nil
}

func (s *OIDCRefreshTokenStore) Get(ctx context.Context, rawToken string) (oidc.RefreshToken, error) {
	selector, err := oidcRefreshSelector(rawToken)
	if err != nil {
		return oidc.RefreshToken{}, oidc.ErrRefreshTokenNotFound
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return oidc.RefreshToken{}, fmt.Errorf("begin OIDC refresh token lookup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	locked, err := lockOIDCRefreshToken(ctx, tx, selector)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !s.matches(rawToken, locked.keyID, locked.digest)) {
		return oidc.RefreshToken{}, oidc.ErrRefreshTokenNotFound
	}
	if err != nil {
		return oidc.RefreshToken{}, err
	}
	record := locked.record(rawToken)
	if locked.consumedAt.Valid {
		replayAt := time.Now().UTC()
		if err := markOIDCRefreshReplay(ctx, tx, locked, replayAt); err != nil {
			return oidc.RefreshToken{}, err
		}
		record.RevokedAt = &replayAt
	}
	if err := tx.Commit(); err != nil {
		return oidc.RefreshToken{}, fmt.Errorf("commit OIDC refresh token lookup: %w", err)
	}

	return record, nil
}

func (s *OIDCRefreshTokenStore) Revoke(ctx context.Context, rawToken string, revokedAt time.Time) error {
	selector, err := oidcRefreshSelector(rawToken)
	if err != nil {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin OIDC refresh token revoke: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	locked, err := lockOIDCRefreshToken(ctx, tx, selector)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !s.matches(rawToken, locked.keyID, locked.digest)) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_oidc_refresh_families
SET revoked_at = COALESCE(revoked_at, $2)
WHERE id = $1`, locked.familyID, revokedAt.UTC()); err != nil {
		return fmt.Errorf("revoke OIDC refresh family: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit OIDC refresh token revoke: %w", err)
	}

	return nil
}

func (s *OIDCRefreshTokenStore) Rotate(
	ctx context.Context,
	currentRaw string,
	next oidc.RefreshToken,
	rotatedAt time.Time,
) error {
	selector, err := oidcRefreshSelector(currentRaw)
	if err != nil {
		return oidc.ErrRefreshTokenNotFound
	}
	nextSubjectID, err := validateOIDCRefreshToken(next)
	if err != nil {
		return err
	}
	nextSelector, nextKeyID, nextDigest, err := s.digestActive(next.Token)
	if err != nil {
		return err
	}
	if selector == nextSelector {
		return errors.New("OIDC refresh rotation must use a new token")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin OIDC refresh token rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	locked, err := lockOIDCRefreshToken(ctx, tx, selector)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !s.matches(currentRaw, locked.keyID, locked.digest)) {
		return oidc.ErrRefreshTokenNotFound
	}
	if err != nil {
		return err
	}
	if locked.consumedAt.Valid {
		if err := markOIDCRefreshReplay(ctx, tx, locked, rotatedAt.UTC()); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit OIDC refresh replay revocation: %w", err)
		}
		return oidc.ErrRefreshTokenReplay
	}
	if locked.revokedAt.Valid || locked.replayedAt.Valid || !rotatedAt.Before(locked.tokenExpiresAt) {
		return oidc.ErrRefreshTokenNotFound
	}
	if nextSubjectID != locked.subjectID || next.ClientID != locked.clientID ||
		oidc.ScopeString(next.Scopes) != locked.scopes || next.SecurityVersion != locked.securityVersion ||
		!next.AuthenticatedAt.Equal(locked.authenticatedAt) {
		return errors.New("OIDC refresh rotation changed immutable family metadata")
	}
	if err := insertOIDCRefreshToken(
		ctx,
		tx,
		nextSelector,
		locked.familyID,
		nextKeyID,
		nextDigest,
		next,
	); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `
UPDATE auth_oidc_refresh_tokens
SET consumed_at = $2, replaced_by_selector = $3
WHERE selector = $1 AND consumed_at IS NULL`, selector, rotatedAt.UTC(), nextSelector)
	if err != nil {
		return fmt.Errorf("consume OIDC refresh token: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errors.New("OIDC refresh consume guard did not update exactly one row")
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_oidc_refresh_families SET expires_at = $2 WHERE id = $1`, locked.familyID, next.ExpiresAt); err != nil {
		return fmt.Errorf("extend OIDC refresh family expiry: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit OIDC refresh token rotation: %w", err)
	}

	return nil
}

type lockedOIDCRefreshToken struct {
	familyID        string
	subjectID       goauth.SubjectID
	clientID        string
	scopes          string
	securityVersion int64
	authenticatedAt time.Time
	familyCreatedAt time.Time
	familyExpiresAt time.Time
	revokedAt       sql.NullTime
	replayedAt      sql.NullTime
	keyID           string
	digest          []byte
	tokenCreatedAt  time.Time
	tokenExpiresAt  time.Time
	consumedAt      sql.NullTime
}

func lockOIDCRefreshToken(
	ctx context.Context,
	tx *sql.Tx,
	selector string,
) (lockedOIDCRefreshToken, error) {
	var token lockedOIDCRefreshToken
	err := tx.QueryRowContext(ctx, `
SELECT
    f.id, f.subject_id, f.client_id, f.scopes, f.security_version,
    f.authenticated_at, f.created_at, f.expires_at, f.revoked_at, f.replayed_at,
    t.key_id, t.secret_digest, t.created_at, t.expires_at, t.consumed_at
FROM auth_oidc_refresh_tokens t
JOIN auth_oidc_refresh_families f ON f.id = t.family_id
WHERE t.selector = $1
FOR UPDATE OF t, f`, selector).Scan(
		&token.familyID,
		&token.subjectID,
		&token.clientID,
		&token.scopes,
		&token.securityVersion,
		&token.authenticatedAt,
		&token.familyCreatedAt,
		&token.familyExpiresAt,
		&token.revokedAt,
		&token.replayedAt,
		&token.keyID,
		&token.digest,
		&token.tokenCreatedAt,
		&token.tokenExpiresAt,
		&token.consumedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return lockedOIDCRefreshToken{}, sql.ErrNoRows
		}
		return lockedOIDCRefreshToken{}, fmt.Errorf("lock OIDC refresh token: %w", err)
	}

	return token, nil
}

func (t lockedOIDCRefreshToken) record(rawToken string) oidc.RefreshToken {
	revokedAt := nullableTimePointer(t.revokedAt)
	if revokedAt == nil {
		revokedAt = nullableTimePointer(t.replayedAt)
	}
	if revokedAt == nil {
		revokedAt = nullableTimePointer(t.consumedAt)
	}

	return oidc.RefreshToken{
		Token:           rawToken,
		SubjectID:       t.subjectID.String(),
		ClientID:        t.clientID,
		Scopes:          oidc.ParseScope(t.scopes),
		SecurityVersion: t.securityVersion,
		AuthenticatedAt: t.authenticatedAt,
		CreatedAt:       t.tokenCreatedAt,
		ExpiresAt:       t.tokenExpiresAt,
		RevokedAt:       revokedAt,
	}
}

func nullableTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time

	return &result
}

func insertOIDCRefreshToken(
	ctx context.Context,
	tx *sql.Tx,
	selector string,
	familyID string,
	keyID string,
	digest []byte,
	token oidc.RefreshToken,
) error {
	if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_oidc_refresh_tokens (
    selector, family_id, key_id, secret_digest, created_at, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6)`,
		selector,
		familyID,
		keyID,
		digest,
		token.CreatedAt,
		token.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert OIDC refresh token: %w", err)
	}

	return nil
}

func markOIDCRefreshReplay(
	ctx context.Context,
	tx *sql.Tx,
	token lockedOIDCRefreshToken,
	replayedAt time.Time,
) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_oidc_refresh_families
SET revoked_at = COALESCE(revoked_at, $2), replayed_at = COALESCE(replayed_at, $2)
WHERE id = $1`, token.familyID, replayedAt); err != nil {
		return fmt.Errorf("revoke replayed OIDC refresh family: %w", err)
	}
	if !token.replayedAt.Valid {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO auth_security_audit_events (
    id, subject_id, event_type, realm, attributes, occurred_at
)
VALUES ($1, $2, 'oidc_refresh.replay', '', jsonb_build_object('client_id', $3::text), $4)`,
			uuid.NewString(),
			token.subjectID,
			token.clientID,
			replayedAt,
		); err != nil {
			return fmt.Errorf("record OIDC refresh replay audit: %w", err)
		}
	}

	return nil
}

func validateOIDCRefreshToken(token oidc.RefreshToken) (goauth.SubjectID, error) {
	subjectID, err := goauth.ParseSubjectID(token.SubjectID)
	if err != nil || strings.TrimSpace(token.Token) == "" || len(token.Token) > maxOIDCRefreshTokenLength ||
		strings.TrimSpace(token.ClientID) == "" || token.SecurityVersion < 1 || token.CreatedAt.IsZero() ||
		token.AuthenticatedAt.IsZero() || !token.ExpiresAt.After(token.CreatedAt) {
		return goauth.NilSubjectID, errors.New("invalid OIDC refresh token record")
	}

	return subjectID, nil
}

func oidcRefreshSelector(rawToken string) (string, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" || len(rawToken) > maxOIDCRefreshTokenLength {
		return "", oidc.ErrRefreshTokenNotFound
	}
	hash := sha256.Sum256([]byte(rawToken))

	return base64.RawURLEncoding.EncodeToString(hash[:16]), nil
}

func (s *OIDCRefreshTokenStore) digestActive(
	rawToken string,
) (selector string, keyID string, digest []byte, err error) {
	selector, err = oidcRefreshSelector(rawToken)
	if err != nil {
		return "", "", nil, err
	}
	key, err := s.keys.Active()
	if err != nil {
		return "", "", nil, err
	}

	return selector, key.ID, oidcRefreshDigest(key, selector, rawToken), nil
}

func (s *OIDCRefreshTokenStore) matches(rawToken, keyID string, expected []byte) bool {
	selector, err := oidcRefreshSelector(rawToken)
	if err != nil {
		return false
	}
	key, err := s.keys.Get(keyID)
	if err != nil {
		return false
	}

	return hmac.Equal(expected, oidcRefreshDigest(key, selector, strings.TrimSpace(rawToken)))
}

func oidcRefreshDigest(key goauth.Key, selector, rawToken string) []byte {
	mac := hmac.New(sha256.New, key.Material)
	_, _ = mac.Write([]byte("oidc-refresh"))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(selector))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strings.TrimSpace(rawToken)))

	return mac.Sum(nil)
}

var _ oidc.RefreshTokenStore = (*OIDCRefreshTokenStore)(nil)
