package goauth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gofiber "github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	goauthfiber "github.com/assurrussa/goauth/fiber"
	authhttp "github.com/assurrussa/goauth/nethttp"
	"github.com/assurrussa/goauth/testkit"
)

func TestReviewEmailQuotaRetryDeadline(t *testing.T) {
	for _, change := range []bool{false, true} {
		for _, window := range []time.Duration{time.Hour, 24 * time.Hour} {
			name := map[bool]string{false: "verification", true: "email-change"}[change] + "/" + window.String()
			t.Run(name, func(t *testing.T) {
				base := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
				now := base
				fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
					config.Now = func() time.Time { return now }
				})
				require.NoError(t, err)
				account := reviewAccount(t, fixture)
				issue := func() error {
					if change {
						return fixture.Runtime.RequestEmailChange(t.Context(), account.Subject.ID, "replacement@example.test")
					}
					return fixture.Runtime.SendEmailChallenge(t.Context(), account.Subject.ID, goauth.EmailChallengePurposeVerification)
				}
				count, spacing := 5, time.Minute
				if window == 24*time.Hour {
					count, spacing = 10, 2*time.Hour
				}
				for index := range count {
					now = base.Add(time.Duration(index) * spacing)
					require.NoError(t, issue())
				}
				before := len(fixture.Events.Events())
				now = base.Add(time.Duration(count-1)*spacing + 30*time.Second)
				err = issue()
				require.ErrorIs(t, err, goauth.ErrConfirmationResendDelay)
				var retry interface{ RetryAfter() time.Duration }
				require.ErrorAs(t, err, &retry)
				require.Equal(t, base.Add(window).Sub(now), retry.RetryAfter(), "the longer quota must determine the deadline")

				now = base.Add(window - time.Minute)
				err = issue()
				require.ErrorIs(t, err, goauth.ErrConfirmationRateLimited)
				require.ErrorAs(t, err, &retry)
				require.Equal(t, time.Minute, retry.RetryAfter())
				assertReviewEmailRetryHeaders(t, err)

				now = base.Add(window)
				require.ErrorIs(t, issue(), goauth.ErrConfirmationRateLimited, "the exact cutoff stays included")
				require.Len(t, fixture.Events.Events(), before, "denials must not enqueue a notification")
				now = now.Add(time.Microsecond)
				require.NoError(t, issue())
				require.Len(t, fixture.Events.Events(), before+1)
			})
		}
	}
}

func assertReviewEmailRetryHeaders(t *testing.T, err error) {
	t.Helper()
	recorder := httptest.NewRecorder()
	authhttp.WriteError(recorder, err)
	require.Equal(t, http.StatusTooManyRequests, recorder.Code)
	require.Equal(t, "60", recorder.Header().Get("Retry-After"))

	app := gofiber.New()
	app.Get("/", func(c gofiber.Ctx) error { return goauthfiber.WriteError(c, err) })
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	response, testErr := app.Test(request)
	require.NoError(t, testErr)
	require.Equal(t, http.StatusTooManyRequests, response.StatusCode)
	require.Equal(t, "60", response.Header.Get("Retry-After"))
	require.NoError(t, response.Body.Close())
}
