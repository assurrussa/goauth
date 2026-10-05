//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/postgres"
)

func sessionOIDCFixture(t *testing.T) (*postgres.Runtime, *postgres.SessionOIDCState, oidc.SessionRefresh) {
	t.Helper()
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	account, err := runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{Email: "session@example.test", Password: "Synthetic-Session-Password-42"})
	require.NoError(t, err)
	state, err := postgres.NewSessionOIDCState(runtime)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	b := oidc.SessionBinding{
		SubjectID: account.Subject.ID.String(), SecurityVersion: account.Subject.SecurityVersion,
		ClientID: "session-client", SessionID: uuid.NewString(), PolicyStamp: "v1:project:1:1:1", AuthenticatedAt: now, AbsoluteExpiresAt: now.Add(7 * 24 * time.Hour),
	}
	r := oidc.SessionRefresh{Binding: b, FamilyID: uuid.NewString(), RefreshToken: oidc.RefreshToken{
		Token: "synthetic-refresh-" + uuid.NewString(), SubjectID: b.SubjectID, SecurityVersion: b.SecurityVersion, ClientID: b.ClientID,
		Scopes: []string{"openid"}, AuthenticatedAt: b.AuthenticatedAt, CreatedAt: now, ExpiresAt: b.AbsoluteExpiresAt,
	}}
	return runtime, state, r
}

func sessionOIDCRequest(now time.Time) oidc.SessionRequest {
	return oidc.SessionRequest{
		ClientRevision: 1, BrowserBinding: "synthetic-browser-digest", Prompt: []string{"login"},
		AuthorizationRequest: oidc.AuthorizationRequest{
			Challenge: "synthetic-challenge-" + uuid.NewString(), ClientID: "session-client",
			RedirectURI: "https://client.example.test/callback", State: "synthetic-state", Nonce: "synthetic-nonce", Scopes: []string{"openid"},
			CodeChallenge: strings.Repeat("x", 43), CodeChallengeMethod: "S256", RequestedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		},
	}
}

func sessionOIDCCode(r oidc.SessionRefresh) oidc.SessionCode {
	return oidc.SessionCode{Binding: r.Binding, AuthorizationCode: oidc.AuthorizationCode{
		Code: "synthetic-code-" + uuid.NewString(), SubjectID: r.SubjectID, SecurityVersion: r.SecurityVersion, ClientID: r.ClientID,
		RedirectURI: "https://client.example.test/callback", Scopes: r.Scopes, Nonce: "synthetic-nonce", CodeChallenge: strings.Repeat("x", 43),
		CodeChallengeMethod: "S256", AuthenticatedAt: r.AuthenticatedAt, CreatedAt: r.CreatedAt, ExpiresAt: r.CreatedAt.Add(time.Minute),
	}}
}

func TestSessionOIDCRequestCompletionOneWayAndAtomic(t *testing.T) {
	runtime, state, refresh := sessionOIDCFixture(t)
	now := refresh.CreatedAt
	ctx := authclock.With(t.Context(), func() time.Time { return now })
	r := sessionOIDCRequest(now)
	age := int64(0)
	r.MaxAgeSeconds = &age
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error { return state.SaveRequest(ctx, r) }))
	completion := oidc.RequestLoginCompletion{SessionID: refresh.Binding.SessionID, CookieDigest: "synthetic-cookie-digest", AuthenticatedAt: now}
	before, err := state.ReadRequest(ctx, r.Challenge)
	require.NoError(t, err)
	require.Nil(t, before.LoginCompletion)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		_, err := state.ConsumeRequest(ctx, r.Challenge)
		require.ErrorIs(t, err, oidc.ErrSessionStateConflict)
		require.ErrorIs(t, state.MarkLoginComplete(ctx, r.Challenge, "wrong-browser", completion), oidc.ErrSessionStateConflict)
		return nil
	}))
	rejected := errors.New("injected rollback")
	require.ErrorIs(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		require.NoError(t, state.MarkLoginComplete(ctx, r.Challenge, r.BrowserBinding, completion))
		return rejected
	}), rejected)
	loaded, err := state.ReadRequest(ctx, r.Challenge)
	require.NoError(t, err)
	require.Nil(t, loaded.LoginCompletion)
	runSessionOIDCRace(t, 2, func() error {
		return state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
			return state.MarkLoginComplete(ctx, r.Challenge, r.BrowserBinding, completion)
		})
	}, oidc.ErrSessionStateConflict)
	loaded, err = state.ReadRequest(ctx, r.Challenge)
	require.NoError(t, err)
	require.Equal(t, completion.SessionID, loaded.LoginCompletion.SessionID)
	require.Equal(t, completion.CookieDigest, loaded.LoginCompletion.CookieDigest)
	require.True(t, completion.AuthenticatedAt.Equal(loaded.LoginCompletion.AuthenticatedAt))
	require.EqualValues(t, 0, *loaded.MaxAgeSeconds)
	require.Equal(t, []string{"login"}, loaded.Prompt)
	runSessionOIDCRace(t, 2, func() error {
		return state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
			_, err := state.ConsumeRequest(ctx, r.Challenge)
			return err
		})
	}, oidc.ErrSessionStateConflict)
	loaded, err = state.ReadRequest(ctx, r.Challenge)
	require.NoError(t, err)
	require.NotNil(t, loaded.ConsumedAt)
	_, err = runtime.Database().Exec(`UPDATE auth_oidc_authorization_requests SET login_cookie_digest='replaced'`)
	require.Error(t, err)
	_, err = runtime.Database().Exec(`UPDATE auth_oidc_authorization_requests SET consumed_at=NULL`)
	require.Error(t, err)
	var raw int
	require.NoError(t, runtime.Database().QueryRow(`SELECT count(*) FROM auth_oidc_authorization_requests WHERE row_to_json(auth_oidc_authorization_requests)::text LIKE '%'||$1||'%'`, r.Challenge).Scan(&raw))
	require.Zero(t, raw)
}

func runSessionOIDCRace(t *testing.T, n int, call func() error, loser error) {
	t.Helper()
	var wg sync.WaitGroup
	var won, lost atomic.Int64
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := call()
			switch {
			case err == nil:
				won.Add(1)
			case errors.Is(err, loser):
				lost.Add(1)
			default:
				t.Errorf("unexpected race outcome: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	require.EqualValues(t, 1, won.Load())
	require.EqualValues(t, n-1, lost.Load())
}

func TestSessionOIDCCodeRefreshReplayAndCrossProfileIsolation(t *testing.T) {
	runtime, state, r := sessionOIDCFixture(t)
	ctx := t.Context()
	code := sessionOIDCCode(r)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error { return state.SaveCode(ctx, code) }))
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		require.NoError(t, state.SaveRefresh(ctx, r))
		_, err := state.ConsumeCode(ctx, code.Code, r.FamilyID, r.CreatedAt)
		return err
	}))
	loadedCode, err := state.ReadCode(ctx, code.Code)
	require.NoError(t, err)
	require.NotNil(t, loadedCode.ConsumedAt)
	require.Equal(t, r.FamilyID, loadedCode.FamilyID)
	next := r
	next.Token = "synthetic-next-" + uuid.NewString()
	next.CreatedAt = r.CreatedAt.Add(time.Minute)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error { return state.RotateRefresh(ctx, r, next, next.CreatedAt) }))
	consumed, err := state.ReadRefresh(ctx, r.Token)
	require.NoError(t, err)
	require.NotNil(t, consumed.ConsumedAt)
	require.Nil(t, consumed.RevokedAt)
	legacy := runtime.OIDCRefreshTokens()
	for _, raw := range []string{r.Token, next.Token} {
		_, err = legacy.Get(ctx, raw)
		require.ErrorIs(t, err, oidc.ErrRefreshTokenNotFound)
		require.NoError(t, legacy.Revoke(ctx, raw, time.Now()))
		alternate := next.RefreshToken
		alternate.Token = "unwanted-" + uuid.NewString()
		require.ErrorIs(t, legacy.Rotate(ctx, raw, alternate, time.Now()), oidc.ErrRefreshTokenNotFound)
	}
	live, err := state.ReadRefresh(ctx, next.Token)
	require.NoError(t, err)
	require.Nil(t, live.RevokedAt)
	var audits, tokens int
	require.NoError(t, runtime.Database().QueryRow(`SELECT count(*) FROM auth_security_audit_events WHERE event_type='oidc_refresh.replay'`).Scan(&audits))
	require.Zero(t, audits)
	require.NoError(t, runtime.Database().QueryRow(`SELECT count(*) FROM auth_oidc_refresh_tokens`).Scan(&tokens))
	require.Equal(t, 2, tokens)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		return state.RevokeFamily(ctx, r.FamilyID, oidc.SessionReplay, time.Now())
	}))
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		return state.RevokeFamily(ctx, r.FamilyID, oidc.SessionReplay, time.Now())
	}))
	live, err = state.ReadRefresh(ctx, next.Token)
	require.NoError(t, err)
	require.NotNil(t, live.RevokedAt)
	require.NoError(t, runtime.Database().QueryRow(`SELECT count(*) FROM auth_security_audit_events WHERE event_type='oidc_refresh.replay'`).Scan(&audits))
	require.Equal(t, 1, audits)
	old := r.RefreshToken
	old.Token = "synthetic-legacy-" + uuid.NewString()
	require.NoError(t, legacy.Save(ctx, old))
	_, err = state.ReadRefresh(ctx, old.Token)
	require.ErrorIs(t, err, oidc.ErrRefreshTokenNotFound)
	var oldFamily string
	require.NoError(t, runtime.Database().QueryRow(`SELECT id FROM auth_oidc_refresh_families WHERE session_id IS NULL`).Scan(&oldFamily))
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		_, err := state.LockRefresh(ctx, old.Token)
		require.ErrorIs(t, err, oidc.ErrRefreshTokenNotFound)
		require.ErrorIs(t, state.RevokeFamily(ctx, oldFamily, oidc.SessionReplay, time.Now()), oidc.ErrRefreshTokenNotFound)
		return nil
	}))
}

func TestSessionOIDCRefusesFamilyBeyondSevenDays(t *testing.T) {
	runtime, state, r := sessionOIDCFixture(t)
	r.Binding.AbsoluteExpiresAt = r.AuthenticatedAt.Add(7*24*time.Hour + time.Second)
	r.ExpiresAt = r.Binding.AbsoluteExpiresAt
	require.Error(t, state.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error { return state.SaveRefresh(ctx, r) }))
	_, err := runtime.Database().Exec(`INSERT INTO auth_oidc_refresh_families
 (id,subject_id,client_id,scopes,security_version,authenticated_at,created_at,expires_at,session_id,authorization_stamp,absolute_expires_at)
 VALUES($1,$2,$3,'openid',$4,$5,$5,$6,$7,$8,$6)`, r.FamilyID, r.SubjectID, r.ClientID, r.SecurityVersion, r.AuthenticatedAt, r.ExpiresAt, r.Binding.SessionID, r.Binding.PolicyStamp)
	require.Error(t, err)
}

func TestSessionOIDCLegacyGetHasNoReplaySideEffects(t *testing.T) {
	runtime, _, r := sessionOIDCFixture(t)
	store := runtime.OIDCRefreshTokens()
	ctx := t.Context()
	require.NoError(t, store.Save(ctx, r.RefreshToken))
	next := r.RefreshToken
	next.Token = "next-" + uuid.NewString()
	next.CreatedAt = r.CreatedAt.Add(time.Second)
	require.NoError(t, store.Rotate(ctx, r.Token, next, next.CreatedAt))
	consumed, err := store.Get(ctx, r.Token)
	require.NoError(t, err)
	require.NotNil(t, consumed.RevokedAt)
	live, err := store.Get(ctx, next.Token)
	require.NoError(t, err)
	require.Nil(t, live.RevokedAt)
	var audits int
	require.NoError(t, runtime.Database().QueryRow(`SELECT count(*) FROM auth_security_audit_events WHERE event_type='oidc_refresh.replay'`).Scan(&audits))
	require.Zero(t, audits)
	require.NoError(t, store.Revoke(ctx, r.Token, time.Now()))
	live, err = store.Get(ctx, next.Token)
	require.NoError(t, err)
	require.NotNil(t, live.RevokedAt)
	require.NoError(t, runtime.Database().QueryRow(`SELECT count(*) FROM auth_security_audit_events WHERE event_type='oidc_refresh.replay'`).Scan(&audits))
	require.Equal(t, 1, audits)
}

func TestSessionOIDCInvariantsAndGlobalRevocation(t *testing.T) {
	runtime, state, r := sessionOIDCFixture(t)
	ctx := t.Context()
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error { return state.SaveRefresh(ctx, r) }))
	for _, change := range []string{
		`session_id=NULL`, `session_id=NULL,authorization_stamp=NULL,absolute_expires_at=NULL`,
		`subject_id='00000000-0000-4000-8000-000000000001'`, `client_id='other'`, `security_version=security_version+1`,
		`authenticated_at=authenticated_at+interval '1 second'`, `expires_at=expires_at+interval '1 day'`,
		`expires_at=expires_at+interval '1 day',absolute_expires_at=absolute_expires_at+interval '1 day'`,
	} {
		_, err := runtime.Database().Exec(`UPDATE auth_oidc_refresh_families SET `+change+` WHERE id=$1`, r.FamilyID)
		require.Error(t, err, change)
	}
	old := r.RefreshToken
	old.Token = "legacy-" + uuid.NewString()
	require.NoError(t, runtime.OIDCRefreshTokens().Save(ctx, old))
	_, err := runtime.Database().Exec(`UPDATE auth_oidc_refresh_families SET session_id='bound',authorization_stamp='v1',absolute_expires_at=expires_at WHERE session_id IS NULL`)
	require.Error(t, err)
	next := r
	next.Token = "next-" + uuid.NewString()
	next.CreatedAt = r.CreatedAt.Add(time.Second)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error { return state.RotateRefresh(ctx, r, next, next.CreatedAt) }))
	for _, change := range []string{`consumed_at=NULL`, `replaced_by_selector=NULL`, `secret_digest=decode(repeat('01',32),'hex')`, `expires_at=expires_at+interval '1 second'`} {
		_, err = runtime.Database().Exec(`UPDATE auth_oidc_refresh_tokens SET `+change+` WHERE family_id=$1 AND consumed_at IS NOT NULL`, r.FamilyID)
		require.Error(t, err, change)
	}
	subjectID, err := goauth.ParseSubjectID(r.SubjectID)
	require.NoError(t, err)
	_, err = runtime.LogoutAll(ctx, subjectID)
	require.NoError(t, err)
	loaded, err := state.ReadRefresh(ctx, next.Token)
	require.NoError(t, err)
	require.NotNil(t, loaded.RevokedAt)
	legacy, err := runtime.OIDCRefreshTokens().Get(ctx, old.Token)
	require.NoError(t, err)
	require.NotNil(t, legacy.RevokedAt)
}

func TestSessionOIDCExpiryAndCleanupRetainLiveTombstones(t *testing.T) {
	runtime, state, r := sessionOIDCFixture(t)
	now := r.CreatedAt
	ctx := authclock.With(t.Context(), func() time.Time { return now })
	code := sessionOIDCCode(r)
	request := sessionOIDCRequest(now)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		if err := state.SaveRequest(ctx, request); err != nil {
			return err
		}
		if err := state.SaveCode(ctx, code); err != nil {
			return err
		}
		if err := state.SaveRefresh(ctx, r); err != nil {
			return err
		}
		_, err := state.ConsumeCode(ctx, code.Code, r.FamilyID, now)
		return err
	}))
	next := r
	next.Token = "next-" + uuid.NewString()
	next.CreatedAt = now.Add(time.Second)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error { return state.RotateRefresh(ctx, r, next, now) }))
	now = now.Add(2 * 24 * time.Hour)
	_, err := runtime.Cleanup(ctx, postgres.CleanupPolicy{Now: func() time.Time { return now }})
	require.NoError(t, err)
	_, err = state.ReadRequest(ctx, request.Challenge)
	require.ErrorIs(t, err, oidc.ErrAuthorizationRequestNotFound)
	retained, err := state.ReadCode(ctx, code.Code)
	require.NoError(t, err)
	require.Equal(t, r.FamilyID, retained.FamilyID)
	used, err := state.ReadRefresh(ctx, r.Token)
	require.NoError(t, err)
	require.NotNil(t, used.ConsumedAt)
	now = r.Binding.AbsoluteExpiresAt
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		another := next
		another.Token = "expired-next"
		another.CreatedAt = now.Add(-time.Second)
		require.ErrorIs(t, state.RotateRefresh(ctx, next, another, now), oidc.ErrRefreshTokenNotFound)
		return nil
	}))
	now = now.Add(2 * 24 * time.Hour)
	_, err = runtime.Cleanup(ctx, postgres.CleanupPolicy{Now: func() time.Time { return now }})
	require.NoError(t, err)
	_, err = state.ReadCode(ctx, code.Code)
	require.ErrorIs(t, err, oidc.ErrAuthorizationCodeNotFound)
	_, err = state.ReadRefresh(ctx, r.Token)
	require.ErrorIs(t, err, oidc.ErrRefreshTokenNotFound)
}

func TestSessionOIDCParallelCodeAndRefreshConsumers(t *testing.T) {
	_, state, r := sessionOIDCFixture(t)
	ctx := t.Context()
	code := sessionOIDCCode(r)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error { return state.SaveCode(ctx, code) }))
	runSessionOIDCRace(t, 8, func() error {
		return state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
			_, err := state.ConsumeCode(ctx, code.Code, "", time.Now())
			return err
		})
	}, oidc.ErrSessionStateConflict)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error { return state.SaveRefresh(ctx, r) }))
	runSessionOIDCRace(t, 8, func() error {
		return state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
			next := r
			next.Token = fmt.Sprintf("parallel-%s", uuid.NewString())
			next.CreatedAt = time.Now()
			return state.RotateRefresh(ctx, r, next, time.Now())
		})
	}, oidc.ErrRefreshTokenReplay)
}

func TestSessionOIDCCleanupSkipsLockedReplayAndRefresh(t *testing.T) {
	for _, lockCode := range []bool{true, false} {
		t.Run(fmt.Sprintf("code-lock-%t", lockCode), func(t *testing.T) {
			runtime, state, r := sessionOIDCFixture(t)
			base := r.CreatedAt
			frozen := authclock.With(t.Context(), func() time.Time { return base })
			code := sessionOIDCCode(r)
			require.NoError(t, state.InOwnedAuthTransaction(frozen, func(ctx context.Context) error {
				if err := state.SaveCode(ctx, code); err != nil {
					return err
				}
				if err := state.SaveRefresh(ctx, r); err != nil {
					return err
				}
				_, err := state.ConsumeCode(ctx, code.Code, r.FamilyID, base)
				return err
			}))
			locked := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				done <- state.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
					if lockCode {
						if _, err := state.LockCode(ctx, code.Code); err != nil {
							return err
						}
					} else {
						if _, err := state.LockRefresh(ctx, r.Token); err != nil {
							return err
						}
					}
					close(locked)
					<-release
					return state.RevokeFamily(ctx, r.FamilyID, oidc.SessionReplay, base.Add(8*24*time.Hour))
				})
			}()
			<-locked
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			result, err := runtime.Cleanup(ctx, postgres.CleanupPolicy{Now: func() time.Time { return base.Add(10 * 24 * time.Hour) }})
			cancel()
			close(release)
			require.NoError(t, <-done)
			require.NoError(t, err)
			require.Zero(t, result.OIDCRefreshFamilies)
			require.Zero(t, result.OIDCRefreshTokens)
			used, err := state.ReadRefresh(t.Context(), r.Token)
			require.NoError(t, err)
			require.NotNil(t, used.RevokedAt)
			_, err = runtime.Cleanup(t.Context(), postgres.CleanupPolicy{Now: func() time.Time { return base.Add(10 * 24 * time.Hour) }})
			require.NoError(t, err)
			_, err = state.ReadRefresh(t.Context(), r.Token)
			require.ErrorIs(t, err, oidc.ErrRefreshTokenNotFound)
		})
	}
}

func TestSessionOIDCCleanupBoundsActualTokenDeletions(t *testing.T) {
	runtime, state, r := sessionOIDCFixture(t)
	base := r.CreatedAt
	ctx := authclock.With(t.Context(), func() time.Time { return base })
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		if err := state.SaveRefresh(ctx, r); err != nil {
			return err
		}
		current := r
		for i := range 1004 {
			next := current
			next.Token = fmt.Sprintf("bounded-chain-%d-%s", i, r.FamilyID)
			if err := state.RotateRefresh(ctx, current, next, base); err != nil {
				return err
			}
			current = next
		}
		return nil
	}))
	future := base.Add(10 * 24 * time.Hour)
	result, err := runtime.Cleanup(t.Context(), postgres.CleanupPolicy{Now: func() time.Time { return future }})
	require.NoError(t, err)
	require.EqualValues(t, 1000, result.OIDCRefreshTokens)
	require.Zero(t, result.OIDCRefreshFamilies)
	var remaining int
	require.NoError(t, runtime.Database().QueryRow(`SELECT count(*) FROM auth_oidc_refresh_tokens WHERE family_id=$1`, r.FamilyID).Scan(&remaining))
	require.Equal(t, 5, remaining)
	result, err = runtime.Cleanup(t.Context(), postgres.CleanupPolicy{Now: func() time.Time { return future }})
	require.NoError(t, err)
	require.EqualValues(t, 5, result.OIDCRefreshTokens)
	require.EqualValues(t, 1, result.OIDCRefreshFamilies)
}

func TestSessionOIDCMarkLoginRechecksClockAfterRequestLock(t *testing.T) {
	runtime, state, r := sessionOIDCFixture(t)
	base := r.CreatedAt
	request := sessionOIDCRequest(base)
	var ticks atomic.Int64
	ticks.Store(base.UnixNano())
	ctx := authclock.With(t.Context(), func() time.Time { return time.Unix(0, ticks.Load()).UTC() })
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error { return state.SaveRequest(ctx, request) }))
	blocker, err := runtime.Database().BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback() }()
	_, err = blocker.Exec(`SELECT 1 FROM auth_oidc_authorization_requests FOR UPDATE`)
	require.NoError(t, err)
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
			close(started)
			return state.MarkLoginComplete(ctx, request.Challenge, request.BrowserBinding,
				oidc.RequestLoginCompletion{SessionID: r.Binding.SessionID, CookieDigest: "digest", AuthenticatedAt: base})
		})
	}()
	<-started
	// Observe the actual SQL lock wait before advancing the injected clock.
	require.Eventually(t, func() bool {
		var waiting bool
		err := runtime.Database().QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity
 WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FROM auth_oidc_authorization_requests WHERE selector=%')`).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, time.Millisecond)
	ticks.Store(request.ExpiresAt.UnixNano())
	require.NoError(t, blocker.Commit())
	require.ErrorIs(t, <-done, oidc.ErrSessionStateConflict)
	loaded, err := state.ReadRequest(ctx, request.Challenge)
	require.NoError(t, err)
	require.Nil(t, loaded.LoginCompletion)
}

func TestSessionOIDCCleanupReleasesLocksBeforeCanonicalCleanup(t *testing.T) {
	runtime, state, r := sessionOIDCFixture(t)
	base := r.CreatedAt
	require.NoError(t, state.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error { return state.SaveRefresh(ctx, r) }))
	id := uuid.NewString()
	_, err := runtime.Database().Exec(`INSERT INTO auth_sessions(id,subject_id,realm,scope,security_version,created_at,expires_at)
 VALUES($1,$2,'user','authenticated',$3,$4,$5)`, id, r.SubjectID, r.SecurityVersion, base, base.Add(time.Hour))
	require.NoError(t, err)
	locked := make(chan struct{})
	release := make(chan struct{})
	writer := make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	go func() {
		writer <- runtime.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
			q, err := runtime.SQLExecutor(ctx)
			if err != nil {
				return err
			}
			if _, err = q.ExecContext(ctx, `SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE`, r.SubjectID); err != nil {
				return err
			}
			if _, err = q.ExecContext(ctx, `SELECT id FROM auth_sessions WHERE id=$1 FOR UPDATE`, id); err != nil {
				return err
			}
			close(locked)
			<-release
			subject, err := goauth.ParseSubjectID(r.SubjectID)
			if err != nil {
				return err
			}
			_, err = runtime.LogoutAll(ctx, subject)
			return err
		})
	}()
	<-locked
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cleaner := make(chan error, 1)
	go func() {
		_, err := runtime.Cleanup(ctx, postgres.CleanupPolicy{Now: func() time.Time { return base.Add(10 * 24 * time.Hour) }})
		cleaner <- err
	}()
	// Canonical cleanup skips the writer's locked subject. It must return and
	// release every OIDC lock while that writer still owns its session lock.
	require.NoError(t, <-cleaner)
	var retained int
	require.NoError(t, runtime.Database().QueryRow(`SELECT count(*) FROM auth_sessions WHERE id=$1`, id).Scan(&retained))
	require.Equal(t, 1, retained)
	unblock()
	require.NoError(t, <-writer)
	result, err := runtime.Cleanup(ctx, postgres.CleanupPolicy{Now: func() time.Time { return base.Add(10 * 24 * time.Hour) }})
	require.NoError(t, err)
	require.EqualValues(t, 1, result.Sessions)
}

func TestSessionOIDCScopedCleanupPreservesLegacyAndGenericState(t *testing.T) {
	runtime, state, r := sessionOIDCFixture(t)
	now := r.CreatedAt
	ctx := authclock.With(t.Context(), func() time.Time { return now })
	request := sessionOIDCRequest(now)
	code := sessionOIDCCode(r)
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		if err := state.SaveRequest(ctx, request); err != nil {
			return err
		}
		if err := state.SaveCode(ctx, code); err != nil {
			return err
		}
		if err := state.SaveRefresh(ctx, r); err != nil {
			return err
		}
		_, err := state.ConsumeCode(ctx, code.Code, r.FamilyID, now)
		return err
	}))
	old := r.RefreshToken
	old.Token = "scoped-cleanup-legacy-" + uuid.NewString()
	require.NoError(t, runtime.OIDCRefreshTokens().Save(ctx, old))
	audit := uuid.NewString()
	_, err := runtime.Database().Exec(`INSERT INTO auth_security_audit_events(id,subject_id,event_type,attributes,occurred_at)
 VALUES($1,$2,'cleanup.retained','{}',$3)`, audit, r.SubjectID, now.Add(-365*24*time.Hour))
	require.NoError(t, err)
	now = r.Binding.AbsoluteExpiresAt
	require.NoError(t, state.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		result, err := state.CleanupExpired(ctx)
		require.ErrorIs(t, err, postgres.ErrAuthTransactionAlreadyActive)
		require.Zero(t, result)
		return nil
	}))
	result, err := state.CleanupExpired(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 1, result.Requests)
	require.EqualValues(t, 1, result.Codes)
	require.EqualValues(t, 1, result.RefreshTokens)
	require.EqualValues(t, 1, result.RefreshFamilies)
	legacy, err := runtime.OIDCRefreshTokens().Get(ctx, old.Token)
	require.NoError(t, err)
	require.Nil(t, legacy.RevokedAt)
	var retained int
	require.NoError(t, runtime.Database().QueryRow(`SELECT count(*) FROM auth_security_audit_events WHERE id=$1`, audit).Scan(&retained))
	require.Equal(t, 1, retained)
	result, err = state.CleanupExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, result)
}

func TestSessionOIDCAbsoluteCapIsIndependentOfDatabaseTimezone(t *testing.T) {
	runtime, _, r := sessionOIDCFixture(t)
	// America/New_York falls back during this seven-day interval. Seven calendar
	// days would incorrectly permit 169 hours, whereas the profile allows 168.
	authenticated := time.Date(2026, time.October, 28, 16, 0, 0, 0, time.UTC)
	for _, extra := range []time.Duration{0, time.Second} {
		tx, err := runtime.Database().BeginTx(t.Context(), nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), `SET LOCAL TIME ZONE 'America/New_York'`)
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), `INSERT INTO auth_oidc_refresh_families
 (id,subject_id,client_id,scopes,security_version,authenticated_at,created_at,expires_at,session_id,authorization_stamp,absolute_expires_at)
 VALUES($1,$2,$3,'openid',$4,$5,$5,$6,$7,$8,$6)`, r.FamilyID, r.SubjectID, r.ClientID, r.SecurityVersion, authenticated,
			authenticated.Add(7*24*time.Hour+extra), r.Binding.SessionID, r.Binding.PolicyStamp)
		if extra == 0 {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
		require.NoError(t, tx.Rollback())
	}
}
