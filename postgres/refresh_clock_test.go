package postgres //nolint:testpackage // Exercise post-lock clock sampling with a synthetic SQL driver.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/oidc"
)

const refreshClockKeyID = "rotation-clock-key"

type refreshClockFixture struct {
	subjectID                          goauth.SubjectID
	origin, tokenExpiry, sessionExpiry time.Time
	consumed                           bool
	onLock                             func()
	digest                             []byte
	writes                             []refreshClockWrite
	commits                            int
}

type refreshClockWrite struct {
	query string
	args  []driver.NamedValue
}

type (
	refreshClockDriver struct{ fixture *refreshClockFixture }
	refreshClockConn   struct {
		notificationRecordingConn
		fixture *refreshClockFixture
	}
)

type (
	refreshClockTx   struct{ fixture *refreshClockFixture }
	refreshClockRows struct{ values []driver.Value }
)

func (d refreshClockDriver) Open(string) (driver.Conn, error) {
	return &refreshClockConn{fixture: d.fixture}, nil
}

func (c *refreshClockConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return refreshClockTx{fixture: c.fixture}, nil
}
func (tx refreshClockTx) Commit() error { tx.fixture.commits++; return nil }
func (refreshClockTx) Rollback() error  { return nil }
func (c *refreshClockConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.fixture.writes = append(c.fixture.writes, refreshClockWrite{query: query, args: append([]driver.NamedValue(nil), args...)})
	return driver.RowsAffected(1), nil
}

func (c *refreshClockConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	f := c.fixture
	if strings.Contains(query, "FOR UPDATE OF") && f.onLock != nil {
		f.onLock()
	}
	var consumed driver.Value
	if f.consumed {
		consumed = f.origin
	}
	switch {
	case strings.Contains(query, "FROM auth_oidc_refresh_tokens t"):
		return &refreshClockRows{values: []driver.Value{
			"family", f.subjectID.String(), "client", "openid", int64(1), f.origin, f.origin, f.sessionExpiry, nil, nil,
			refreshClockKeyID, f.digest, f.origin, f.tokenExpiry, consumed, nil, nil, nil,
		}}, nil
	case strings.Contains(query, "FROM auth_refresh_tokens rt"):
		return &refreshClockRows{values: []driver.Value{
			refreshClockKeyID, f.digest, f.tokenExpiry, consumed, "family", nil, nil, "session", f.subjectID.String(),
			string(goauth.RealmUser), string(goauth.SessionScopeAuthenticated), int64(1), f.origin, f.sessionExpiry, nil,
			string(goauth.SubjectStatusActive), int64(1),
		}}, nil
	case strings.Contains(query, "JOIN auth_identifiers"):
		return &refreshClockRows{values: []driver.Value{
			f.subjectID.String(), string(goauth.SubjectStatusActive), int64(1), f.origin, f.origin,
			"email", string(goauth.IdentifierSchemeEmail), "clock@example.test", "clock@example.test", nil,
			f.origin, f.origin, "", "", "", "",
		}}, nil
	case strings.Contains(query, "SELECT f.subject_id"), strings.Contains(query, "SELECT id FROM auth_subjects"):
		return &refreshClockRows{values: []driver.Value{f.subjectID.String()}}, nil
	default:
		return nil, fmt.Errorf("unexpected fixture query: %s", query)
	}
}
func (r *refreshClockRows) Columns() []string { return make([]string, len(r.values)) }
func (*refreshClockRows) Close() error        { return nil }
func (r *refreshClockRows) Next(dest []driver.Value) error {
	if r.values == nil {
		return io.EOF
	}
	copy(dest, r.values)
	r.values = nil
	return nil
}

func openRefreshClockDB(t *testing.T, f *refreshClockFixture) *sql.DB {
	t.Helper()
	name := "goauth-refresh-clock-" + uuid.NewString()
	sql.Register(name, refreshClockDriver{fixture: f})
	db, err := sql.Open(name, "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

func TestRefreshRotationRechecksExpiryAfterStorageLocks(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                                 string
		delay, tokenTTL, sessionTTL, nextTTL time.Duration
		consumed, peek, direct               bool
		want                                 goauth.RefreshRotationStatus
		writes                               int
	}{
		{
			name: "fixed clock", tokenTTL: time.Minute, sessionTTL: time.Hour, nextTTL: time.Minute,
			want: goauth.RefreshRotationSucceeded, writes: 2,
		},
		{
			name: "offset clock advances", delay: time.Second, tokenTTL: time.Minute, sessionTTL: time.Hour, nextTTL: time.Minute,
			want: goauth.RefreshRotationSucceeded, writes: 2,
		},
		{
			name: "current token expires at lock", delay: time.Second, tokenTTL: time.Second, sessionTTL: time.Hour, nextTTL: time.Minute,
			want: goauth.RefreshRotationExpired,
		},
		{
			name: "session expires at lock", delay: time.Second, tokenTTL: time.Hour, sessionTTL: time.Second, nextTTL: time.Minute,
			want: goauth.RefreshRotationExpired,
		},
		{
			name: "prepared successor expires at lock", delay: time.Second, tokenTTL: time.Minute,
			sessionTTL: time.Hour, nextTTL: time.Second,
			want: goauth.RefreshRotationExpired,
		},
		{
			name: "peek rechecks expiry", delay: time.Second, tokenTTL: time.Second, sessionTTL: time.Hour, nextTTL: time.Minute,
			peek: true, want: goauth.RefreshRotationExpired,
		},
		{
			name: "direct call preserves time origin", direct: true, tokenTTL: time.Minute, sessionTTL: time.Hour, nextTTL: time.Minute,
			want: goauth.RefreshRotationSucceeded, writes: 2,
		},
		{
			name: "authenticated replay precedes expiry", delay: time.Second, tokenTTL: time.Second,
			sessionTTL: time.Second, nextTTL: time.Second, consumed: true, want: goauth.RefreshRotationReplayed, writes: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			origin := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
			now := origin
			f := &refreshClockFixture{
				subjectID: goauth.NewSubjectID(), origin: origin,
				tokenExpiry: origin.Add(tc.tokenTTL), sessionExpiry: origin.Add(tc.sessionTTL), consumed: tc.consumed,
				digest: make([]byte, 32), onLock: func() { now = origin.Add(tc.delay) },
			}
			store, err := NewStore(openRefreshClockDB(t, f))
			require.NoError(t, err)
			request := goauth.RefreshRotationRequest{
				CurrentSelector: "current", CurrentDigest: goauth.SecretDigest{KeyID: refreshClockKeyID, Digest: f.digest},
				NextSelector: "next", NextDigest: goauth.SecretDigest{KeyID: refreshClockKeyID, Digest: make([]byte, 32)},
				NextExpiresAt: origin.Add(tc.nextTTL), Now: origin,
			}
			ctx := t.Context()
			if !tc.direct {
				ctx = authclock.With(ctx, func() time.Time { return now })
			}
			result, err := store.rotateRefresh(ctx, request, tc.peek)
			require.NoError(t, err)
			require.Equal(t, tc.want, result.Status)
			require.Len(t, f.writes, tc.writes, "expiry rejection must not consume or insert tokens")
			if tc.writes == 0 {
				require.Zero(t, f.commits)
				return
			}
			require.Equal(t, 1, f.commits)
			if tc.want == goauth.RefreshRotationSucceeded && !tc.direct {
				require.Equal(t, now, f.writes[0].args[4].Value)
				require.Equal(t, now, f.writes[1].args[1].Value)
			}
			if tc.direct {
				actual, ok := f.writes[0].args[4].Value.(time.Time)
				require.True(t, ok)
				require.True(t, actual.After(origin))
				require.True(t, actual.Before(origin.Add(time.Minute)), "must not substitute wall-clock time")
			}
		})
	}
}

func TestOIDCRefreshRotationRechecksExpiryAfterStorageLocks(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                     string
		delay, tokenTTL, nextTTL time.Duration
		consumed, direct         bool
		want                     error
		writes                   int
	}{
		{name: "fixed clock", tokenTTL: time.Minute, nextTTL: time.Hour, writes: 3},
		{name: "offset clock advances", delay: time.Second, tokenTTL: time.Minute, nextTTL: time.Hour, writes: 3},
		{
			name: "current token expires at lock", delay: time.Second, tokenTTL: time.Second, nextTTL: time.Hour,
			want: oidc.ErrRefreshTokenNotFound,
		},
		{
			name: "successor expires at lock", delay: time.Second, tokenTTL: time.Hour, nextTTL: time.Second,
			want: oidc.ErrRefreshTokenNotFound,
		},
		{
			name: "authenticated replay precedes expiry", delay: time.Second, tokenTTL: time.Second, nextTTL: time.Second,
			consumed: true, want: oidc.ErrRefreshTokenReplay, writes: 2,
		},
		{name: "direct call preserves time origin", direct: true, tokenTTL: time.Minute, nextTTL: time.Hour, writes: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			origin := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
			now := origin
			f := &refreshClockFixture{
				subjectID: goauth.NewSubjectID(), origin: origin,
				tokenExpiry: origin.Add(tc.tokenTTL), sessionExpiry: origin.Add(tc.tokenTTL), consumed: tc.consumed,
				onLock: func() { now = origin.Add(tc.delay) },
			}
			keys, err := goauth.NewKeyRing(refreshClockKeyID, goauth.Key{ID: refreshClockKeyID, Material: []byte(strings.Repeat("k", 32))})
			require.NoError(t, err)
			store, err := NewOIDCRefreshTokenStore(openRefreshClockDB(t, f), keys)
			require.NoError(t, err)
			_, _, f.digest, err = store.digestActive("current")
			require.NoError(t, err)
			next := oidc.RefreshToken{
				Token: "next", SubjectID: f.subjectID.String(), ClientID: "client", Scopes: []string{oidc.ScopeOpenID},
				SecurityVersion: 1, AuthenticatedAt: origin, CreatedAt: origin, ExpiresAt: origin.Add(tc.nextTTL),
			}
			ctx := t.Context()
			if !tc.direct {
				ctx = authclock.With(ctx, func() time.Time { return now })
			}
			err = store.Rotate(ctx, "current", next, origin)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, f.writes, tc.writes, "expiry rejection must not consume or insert tokens")
			if tc.writes == 0 {
				require.Zero(t, f.commits)
				return
			}
			require.Equal(t, 1, f.commits)
			if tc.want == nil && !tc.direct {
				require.Equal(t, now, f.writes[1].args[1].Value)
			}
			if tc.direct {
				actual, ok := f.writes[1].args[1].Value.(time.Time)
				require.True(t, ok)
				require.True(t, actual.After(origin))
				require.True(t, actual.Before(origin.Add(time.Minute)), "must not substitute wall-clock time")
			}
		})
	}
}
