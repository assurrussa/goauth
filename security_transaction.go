package goauth

import (
	"context"
	"time"

	"github.com/assurrussa/goauth/internal/authclock"
)

func (r *Runtime) inSecurityTransaction(ctx context.Context, fn func(context.Context) error) error {
	return r.authTransaction.InAuthTransaction(authclock.With(ctx, r.now), fn)
}

func (r *Runtime) lockActiveAccount(ctx context.Context, id SubjectID) (Account, error) {
	account, err := r.store.LockAccount(ctx, id)
	if err != nil {
		return Account{}, err
	}
	if account.Subject.Status != SubjectStatusActive {
		return Account{}, ErrAccountUnavailable
	}
	return account, nil
}

func (r *Runtime) lockExpectedAccount(ctx context.Context, expected Account) error {
	current, err := r.lockActiveAccount(ctx, expected.Subject.ID)
	if err != nil {
		return err
	}
	if current.Subject.SecurityVersion != expected.Subject.SecurityVersion ||
		current.PrimaryEmail.ID != expected.PrimaryEmail.ID ||
		current.PrimaryEmail.NormalizedValue != expected.PrimaryEmail.NormalizedValue {
		return ErrSecurityVersionMismatch
	}
	return nil
}

// rateLimitError retains errors.Is compatibility and carries the actual retry
// deadline. Transports can use errors.As with interface{ RetryAfter() time.Duration }.
type rateLimitError struct {
	cause   error
	retryAt time.Time
	now     func() time.Time
}

func (e *rateLimitError) Error() string { return e.cause.Error() }
func (e *rateLimitError) Unwrap() error { return e.cause }
func (e *rateLimitError) RetryAfter() time.Duration {
	remaining := e.retryAt.Sub(e.now())
	if remaining < time.Second {
		return time.Second
	}
	return remaining
}

func (r *Runtime) limited(cause error, retryAt time.Time) error {
	if retryAt.IsZero() {
		return cause
	}
	return &rateLimitError{cause: cause, retryAt: retryAt, now: r.now}
}

func (r *Runtime) limitPasswordChange(ctx context.Context, id SubjectID) error {
	digest, err := r.secretCodec.DigestActive("rate-limit:password-change", id.String())
	if err != nil {
		return err
	}
	result, err := r.store.TakeRateLimit(ctx, RateLimitRequest{
		Action: "password_change", Bucket: digest,
		Window: r.loginRateLimit.Window, Limit: r.loginRateLimit.Limit, Now: r.now().UTC(),
	})
	if err != nil {
		return err
	}
	if !result.Allowed {
		return r.limited(ErrAuthenticationRateLimited, result.RetryAt)
	}
	return nil
}
