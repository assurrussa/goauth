package goauth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/assurrussa/goauth"
	authhttp "github.com/assurrussa/goauth/nethttp"
	"github.com/assurrussa/goauth/testkit"
)

const (
	customHasherLoginOperation               = "login"
	customHasherCurrentPasswordOperation     = "current password"
	customHasherReplacementPasswordOperation = "replacement password"
)

type legacyBcryptHasher struct {
	wrap            func(error) error
	failure         error
	failurePassword string
}

func (*legacyBcryptHasher) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return string(hash), err
}

func (h *legacyBcryptHasher) VerifyPassword(hash, password string) error {
	if h.failure != nil && (h.failurePassword == "" || h.failurePassword == password) {
		return h.failure
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil && h.wrap != nil {
		return h.wrap(err)
	}
	return err
}

func TestCustomPasswordHasherNativeMismatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		wrap func(error) error
	}{
		{name: "native"},
		{name: "wrapped", wrap: func(err error) error { return fmt.Errorf("legacy verifier: %w", err) }},
		{name: "joined", wrap: func(err error) error { return errors.Join(errors.New("legacy mismatch"), err) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hasher := &legacyBcryptHasher{wrap: tc.wrap}
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) { c.PasswordHasher = hasher })
			require.NoError(t, err)
			const email = "legacy.hasher@example.test"
			registered := registerAccount(t, fixture, email)
			wrong := loginRequest(email, "Incorrect-Legacy-Passphrase-1", goauth.RealmUser)
			t.Run(customHasherLoginOperation, func(t *testing.T) {
				_, err := fixture.Runtime.Login(t.Context(), wrong)
				require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
			})
			t.Run("verify credential", func(t *testing.T) {
				_, err := fixture.Runtime.VerifyCredential(t.Context(), wrong.Credential)
				require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
			})
			t.Run("missing account", func(t *testing.T) {
				missing := loginRequest("missing.hasher@example.test", wrong.Credential.Password, goauth.RealmUser)
				_, err := fixture.Runtime.Login(t.Context(), missing)
				require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
				_, err = fixture.Runtime.VerifyCredential(t.Context(), missing.Credential)
				require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
			})
			t.Run("incorrect current password", func(t *testing.T) {
				_, err := fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
					SubjectID: registered.Account.Subject.ID, CurrentPassword: wrong.Credential.Password,
					NewPassword: "Replacement-Legacy-Passphrase-2",
				})
				require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
			})
			account, err := fixture.Runtime.GetAccount(t.Context(), registered.Account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, registered.Account, account)
			require.Empty(t, fixture.Events.Events())
			_, err = fixture.Runtime.VerifyCredential(t.Context(), loginRequest(email, testPassword, goauth.RealmUser).Credential)
			require.NoError(t, err)
			_, err = fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
				SubjectID: account.Subject.ID, CurrentPassword: testPassword, NewPassword: testPassword,
			})
			require.ErrorIs(t, err, goauth.ErrPasswordUnchanged)
			const replacement = "Replacement-Legacy-Passphrase-2"
			changed, err := fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
				SubjectID: account.Subject.ID, CurrentPassword: testPassword, NewPassword: replacement,
			})
			require.NoError(t, err)
			require.Equal(t, account.Subject.SecurityVersion+1, changed.Subject.SecurityVersion)
			_, err = fixture.Runtime.VerifyCredential(t.Context(), loginRequest(email, replacement, goauth.RealmUser).Credential)
			require.NoError(t, err)
			_, err = fixture.Runtime.AuthenticateSession(t.Context(), registered.Tokens.AccessToken)
			require.ErrorIs(t, err, goauth.ErrSessionRevoked)
		})
	}
}

func TestCustomPasswordHasherOperationalFailures(t *testing.T) {
	t.Parallel()
	fault := errors.New("synthetic verifier backend outage")
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{name: "marked", err: goauth.ErrPasswordVerificationUnavailable, status: http.StatusServiceUnavailable},
		{
			name: "wrapped", err: fmt.Errorf("verifier: %w: %w", goauth.ErrPasswordVerificationUnavailable, fault),
			status: http.StatusServiceUnavailable,
		},
		{name: "joined", err: errors.Join(goauth.ErrPasswordVerificationUnavailable, fault), status: http.StatusServiceUnavailable},
		{name: "overload", err: fmt.Errorf("verifier: %w", goauth.ErrPasswordHashOverloaded), status: http.StatusServiceUnavailable},
		{name: "cancellation", err: fmt.Errorf("verifier: %w", context.Canceled), status: http.StatusServiceUnavailable},
		{name: "deadline", err: fmt.Errorf("verifier: %w", context.DeadlineExceeded), status: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, operation := range []string{
				customHasherLoginOperation, "verify credential",
				customHasherCurrentPasswordOperation, customHasherReplacementPasswordOperation,
			} {
				t.Run(operation, func(t *testing.T) {
					hasher := &legacyBcryptHasher{}
					fixture, err := testkit.NewRuntime(func(c *goauth.Config) { c.PasswordHasher = hasher })
					require.NoError(t, err)
					const email = "hasher.outage@example.test"
					registered := registerAccount(t, fixture, email)
					hasher.failure = tc.err
					const replacement = "Replacement-Legacy-Passphrase-2"
					if operation == customHasherReplacementPasswordOperation {
						hasher.failurePassword = replacement
					}
					switch operation {
					case customHasherLoginOperation:
						_, err = fixture.Runtime.Login(t.Context(), loginRequest(email, testPassword, goauth.RealmUser))
					case "verify credential":
						_, err = fixture.Runtime.VerifyCredential(t.Context(), loginRequest(email, testPassword, goauth.RealmUser).Credential)
					default:
						_, err = fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
							SubjectID: registered.Account.Subject.ID, CurrentPassword: testPassword, NewPassword: replacement,
						})
					}
					require.ErrorIs(t, err, tc.err)
					if errors.Is(tc.err, fault) {
						require.ErrorIs(t, err, fault)
					}
					require.NotErrorIs(t, err, goauth.ErrInvalidCredentials)
					require.NotErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
					response := httptest.NewRecorder()
					authhttp.WriteError(response, err)
					require.Equal(t, tc.status, response.Code)
					require.NotContains(t, response.Body.String(), fault.Error())
					account, err := fixture.Runtime.GetAccount(t.Context(), registered.Account.Subject.ID)
					require.NoError(t, err)
					require.Equal(t, registered.Account, account)
					require.Empty(t, fixture.Events.Events())
					hasher.failure = nil
					_, err = fixture.Runtime.VerifyCredential(t.Context(), loginRequest(email, testPassword, goauth.RealmUser).Credential)
					require.NoError(t, err)
					_, err = fixture.Runtime.AuthenticateSession(t.Context(), registered.Tokens.AccessToken)
					require.NoError(t, err)
				})
			}
		})
	}
}
