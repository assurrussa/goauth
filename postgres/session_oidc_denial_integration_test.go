//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/oidc/provider"
	"github.com/assurrussa/goauth/postgres"
)

// The host owns registration storage. This fixture shares project/client row
// locks between denied admission and callback edits through the real Runtime.
type sessionDenialAdmission struct {
	runtime     *postgres.Runtime
	subjectID   string
	pid         chan int
	afterLocked func()
}

func (a sessionDenialAdmission) Lock(ctx context.Context, input oidc.SessionAdmissionRequest) (oidc.SessionAdmissionResult, error) {
	q, err := a.runtime.SQLExecutor(ctx)
	if err != nil {
		return oidc.SessionAdmissionResult{}, err
	}
	var pid int
	if err := q.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		return oidc.SessionAdmissionResult{}, err
	}
	a.pid <- pid
	var id string
	if err := q.QueryRowContext(ctx, `SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE`, a.subjectID).Scan(&id); err != nil {
		return oidc.SessionAdmissionResult{}, err
	}
	if err := q.QueryRowContext(ctx, `SELECT id FROM session_denial_project FOR UPDATE`).Scan(&id); err != nil {
		return oidc.SessionAdmissionResult{}, err
	}
	var callback string
	current := oidc.SessionAdmissionResult{Client: oidc.Client{ID: input.ClientID, Trusted: true}}
	if err := q.QueryRowContext(ctx, `SELECT callback, revision FROM session_denial_client WHERE id=$1 FOR UPDATE`, input.ClientID).
		Scan(&callback, &current.ClientRevision); err != nil {
		return oidc.SessionAdmissionResult{}, err
	}
	current.Client.RedirectURIs = []string{callback}
	if a.afterLocked != nil {
		a.afterLocked()
	}
	return current, nil // Revoked membership: callback remains known, issuance denied.
}

func waitSessionDenialLock(t *testing.T, db *sql.DB, pid int) {
	t.Helper()
	require.Eventually(t, func() bool {
		var waiting bool
		err := db.QueryRowContext(t.Context(), `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting)
		return err == nil && waiting
	}, 3*time.Second, time.Millisecond)
}

func TestSessionOIDCContinuationDenialSerializesCallbackEdits(t *testing.T) {
	for _, order := range []string{"edit first", "denial first", "expiry after lock wait"} {
		t.Run(order, func(t *testing.T) {
			runtime, state, refresh := sessionOIDCFixture(t)
			db := runtime.Database()
			_, err := db.Exec(`CREATE TABLE session_denial_project(id TEXT PRIMARY KEY);
CREATE TABLE session_denial_client(id TEXT PRIMARY KEY, callback TEXT NOT NULL, revision BIGINT NOT NULL);
INSERT INTO session_denial_project VALUES('synthetic-project')`)
			require.NoError(t, err)
			t.Cleanup(func() {
				_, dropErr := db.Exec(`DROP TABLE session_denial_client; DROP TABLE session_denial_project`)
				require.NoError(t, dropErr)
			})
			request := sessionOIDCRequest(refresh.CreatedAt)
			request.BrowserBinding = strings.Repeat("b", 64)
			request.State = "stored + & / ? state"
			browser := &oidc.BrowserSession{SessionID: refresh.Binding.SessionID, CookieDigest: strings.Repeat("c", 64)}
			_, err = db.Exec(`INSERT INTO session_denial_client VALUES($1,$2,1)`, request.ClientID, request.RedirectURI)
			require.NoError(t, err)
			require.NoError(t, state.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
				if err := state.SaveRequest(ctx, request); err != nil {
					return err
				}
				return state.MarkLoginComplete(ctx, request.Challenge, request.BrowserBinding, oidc.RequestLoginCompletion{
					SessionID: browser.SessionID, CookieDigest: browser.CookieDigest, AuthenticatedAt: refresh.CreatedAt,
				})
			}))
			var clock atomic.Int64
			clock.Store(refresh.CreatedAt.UnixNano())
			admission := sessionDenialAdmission{runtime: runtime, subjectID: refresh.SubjectID, pid: make(chan int, 1)}
			locked, release := make(chan struct{}), make(chan struct{})
			if order == "denial first" {
				admission.afterLocked = func() { close(locked); <-release }
			}
			service, err := provider.NewSessionBound(provider.SessionOptions{
				State: state, Admission: admission, Keys: oidcKeyStoreStub{}, Issuer: "https://issuer.example.test",
				ClientSecretVerifier: oidc.ClientSecretVerifierFunc(func(context.Context, string, string) error { return nil }),
				Now:                  func() time.Time { return time.Unix(0, clock.Load()).UTC() },
			})
			require.NoError(t, err)
			type outcome struct {
				result *oidc.AuthorizeResult
				err    error
			}
			done := make(chan outcome, 1)
			continueRequest := func() {
				result, err := service.ContinueAuthorization(t.Context(), request.Challenge, browser, request.BrowserBinding)
				done <- outcome{result, err}
			}
			const replacement = "https://replacement.example.test/callback"
			if order == "denial first" {
				go continueRequest()
				<-admission.pid
				<-locked
				editPID, edited := make(chan int, 1), make(chan error, 1)
				go func() {
					edited <- runtime.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
						q, err := runtime.SQLExecutor(ctx)
						if err != nil {
							return err
						}
						var pid int
						if err := q.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
							return err
						}
						editPID <- pid
						var id string
						if err := q.QueryRowContext(ctx, `SELECT id FROM session_denial_project FOR UPDATE`).Scan(&id); err != nil {
							return err
						}
						_, err = q.ExecContext(ctx, `UPDATE session_denial_client SET callback=$1, revision=revision+1`, replacement)
						return err
					})
				}()
				waitSessionDenialLock(t, db, <-editPID)
				close(release)
				require.NoError(t, <-edited)
			} else {
				edit, err := db.BeginTx(t.Context(), nil)
				require.NoError(t, err)
				defer func() { _ = edit.Rollback() }()
				var id string
				require.NoError(t, edit.QueryRowContext(t.Context(), `SELECT id FROM session_denial_project FOR UPDATE`).Scan(&id))
				if order == "edit first" {
					_, err = edit.ExecContext(t.Context(), `UPDATE session_denial_client SET callback=$1, revision=revision+1`, replacement)
					require.NoError(t, err)
				}
				go continueRequest()
				waitSessionDenialLock(t, db, <-admission.pid)
				if order == "expiry after lock wait" {
					clock.Store(request.ExpiresAt.UnixNano())
				}
				require.NoError(t, edit.Commit())
			}
			observed := <-done
			stored, err := state.ReadRequest(t.Context(), request.Challenge)
			require.NoError(t, err)
			if order == "denial first" {
				require.NoError(t, observed.err)
				require.NotNil(t, observed.result)
				callback, err := url.Parse(observed.result.RedirectURI)
				require.NoError(t, err)
				require.Equal(t, []string{"access_denied"}, callback.Query()["error"])
				require.Equal(t, []string{request.State}, callback.Query()["state"])
				require.NotContains(t, callback.Query(), "code")
				callback.RawQuery = ""
				require.Equal(t, request.RedirectURI, callback.String())
				require.NotNil(t, stored.ConsumedAt)
				result, replayErr := service.ContinueAuthorization(t.Context(), request.Challenge, browser, request.BrowserBinding)
				require.Nil(t, result)
				var protocol *oidc.OAuthError
				require.ErrorAs(t, replayErr, &protocol)
				require.Equal(t, "invalid_request", protocol.Code)
			} else {
				require.Nil(t, observed.result)
				var protocol *oidc.OAuthError
				require.ErrorAs(t, observed.err, &protocol)
				want := "access_denied"
				if order == "expiry after lock wait" {
					want = "invalid_request"
				}
				require.Equal(t, want, protocol.Code)
				require.Nil(t, stored.ConsumedAt)
			}
			for _, table := range []string{"auth_oidc_authorization_codes", "auth_oidc_refresh_families", "auth_oidc_refresh_tokens"} {
				var count int
				require.NoError(t, db.QueryRowContext(t.Context(), `SELECT count(*) FROM `+table).Scan(&count))
				require.Zero(t, count, table)
			}
		})
	}
}
