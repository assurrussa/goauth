package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/oidc"
)

// SessionOIDCState is the transaction-bound, digest-only OIDC state adapter.
// It never authenticates a host session: callers must perform SessionAdmission
// before taking request/code/family/token locks. Every mutation requires the
// supplied Runtime's managed database transaction.
type SessionOIDCState struct{ runtime *Runtime }

const sessionOIDCForUpdate = " FOR UPDATE"

func NewSessionOIDCState(runtime *Runtime) (*SessionOIDCState, error) {
	if runtime == nil || runtime.store == nil || runtime.oidcRefreshTokens == nil {
		return nil, errors.New("PostgreSQL Runtime is not initialized")
	}
	return &SessionOIDCState{runtime: runtime}, nil
}

func (s *SessionOIDCState) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	return s.runtime.InOwnedAuthTransaction(ctx, fn)
}

func (s *SessionOIDCState) transaction(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.runtime.store.notificationTx(ctx)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, errors.New("session OIDC state requires managed auth transaction")
	}
	return tx, nil
}

func (s *SessionOIDCState) now(ctx context.Context) time.Time {
	started := time.Now()
	origin := started
	if s.runtime.notificationNow != nil {
		origin = s.runtime.notificationNow()
	}
	return authclock.Now(ctx, origin, started)
}

func (s *SessionOIDCState) digest(purpose, raw string) (selector, keyID string, digest []byte, err error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", "", nil, errors.New("invalid OIDC secret")
	}
	selector, err = oidcRefreshSelector(raw)
	if err != nil {
		return "", "", nil, err
	}
	key, err := s.runtime.oidcRefreshTokens.keys.Active()
	if err != nil {
		return "", "", nil, err
	}
	return selector, key.ID, sessionOIDCDigest(key, purpose, selector, raw), nil
}

func (s *SessionOIDCState) matches(purpose, raw, keyID string, digest []byte) bool {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return false
	}
	selector, err := oidcRefreshSelector(raw)
	if err != nil {
		return false
	}
	key, err := s.runtime.oidcRefreshTokens.keys.Get(keyID)
	return err == nil && hmac.Equal(digest, sessionOIDCDigest(key, purpose, selector, raw))
}

func sessionOIDCDigest(key goauth.Key, purpose, selector, raw string) []byte {
	mac := hmac.New(sha256.New, key.Material)
	_, _ = mac.Write([]byte(purpose + "\x00" + selector + "\x00" + raw))
	return mac.Sum(nil)
}

func validateSessionBinding(b oidc.SessionBinding) error {
	if _, err := goauth.ParseSubjectID(b.SubjectID); err != nil {
		return errors.New("invalid OIDC session subject")
	}
	if b.SecurityVersion < 1 || b.ClientID == "" || len(b.ClientID) > 256 || b.SessionID == "" || len(b.SessionID) > 256 ||
		b.PolicyStamp == "" || len(b.PolicyStamp) > 192 || b.AuthenticatedAt.IsZero() ||
		!b.AbsoluteExpiresAt.After(b.AuthenticatedAt) ||
		b.AbsoluteExpiresAt.After(b.AuthenticatedAt.Add(7*24*time.Hour)) {
		return errors.New("invalid OIDC session binding")
	}
	for _, b := range []byte(b.PolicyStamp) {
		if b < 0x21 || b > 0x7e {
			return errors.New("invalid OIDC authorization stamp")
		}
	}
	return nil
}

func equalSessionBinding(a, b oidc.SessionBinding) bool {
	return a.SubjectID == b.SubjectID && a.SecurityVersion == b.SecurityVersion && a.ClientID == b.ClientID &&
		a.SessionID == b.SessionID && a.PolicyStamp == b.PolicyStamp && a.AuthenticatedAt.Equal(b.AuthenticatedAt) &&
		a.AbsoluteExpiresAt.Equal(b.AbsoluteExpiresAt)
}

func sessionTransition(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return oidc.ErrSessionStateConflict
	}
	return nil
}

var _ oidc.SessionStateStore = (*SessionOIDCState)(nil)
