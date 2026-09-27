package passwordreset_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
	"github.com/assurrussa/goauth/internal/legacy/local/passwordreset"
	authshared "github.com/assurrussa/goauth/internal/legacy/shared"
)

func TestServiceRequestUserNotFound(t *testing.T) {
	store := &passwordResetStoreFake{}
	outbox := &outboxFake{}
	svc := passwordreset.Must(passwordreset.Options{
		Reader:        subjectReaderFake{},
		Writer:        subjectWriterFake{},
		Tokens:        store,
		Hasher:        passwordHasherFake{},
		Tx:            txManagerFake{},
		Outbox:        outbox,
		BaseURL:       "https://front.local", //nolint:goconst // autofix
		TTLMinutes:    60,
		Now:           fixedNow,
		GenerateToken: func() (string, error) { return "tok", nil }, //nolint:goconst // autofix
	})

	err := svc.Request(context.Background(), "missing@test.com")

	require.NoError(t, err)
	require.False(t, store.upsertCalled)
	require.Empty(t, outbox.calls)
}

func TestServiceRequestSuccess(t *testing.T) {
	store := &passwordResetStoreFake{}
	outbox := &outboxFake{}
	subject := authcore.Subject{
		ID:    authshared.NewSubjectID(),
		Kind:  authcore.SubjectKindUser,
		Email: "user@test.com", //nolint:goconst // autofix
	}
	svc := passwordreset.Must(passwordreset.Options{
		Reader: subjectReaderFake{
			getByEmailFn: func(_ context.Context, email string) (authcore.Subject, error) {
				require.Equal(t, "user@test.com", email)
				return subject, nil
			},
		},
		Writer:        subjectWriterFake{},
		Tokens:        store,
		Hasher:        passwordHasherFake{},
		Tx:            txManagerFake{},
		Outbox:        outbox,
		BaseURL:       "https://front.local",
		TTLMinutes:    60,
		Now:           fixedNow,
		GenerateToken: func() (string, error) { return "tok", nil },
	})

	err := svc.Request(context.Background(), "user@test.com")

	require.NoError(t, err)
	require.True(t, store.upsertCalled)
	require.Equal(t, "tok", store.lastToken.Token)
	require.Len(t, outbox.calls, 1)
	require.Contains(t, outbox.calls[0].payload, "password_reset")
}

func TestServicePerformInvalidToken(t *testing.T) {
	store := &passwordResetStoreFake{
		getByEmailFn: func(_ context.Context, _ string) (authcore.PasswordResetToken, error) {
			return authcore.PasswordResetToken{}, errors.New("no rows")
		},
	}
	svc := passwordreset.Must(passwordreset.Options{
		Reader:        subjectReaderFake{},
		Writer:        subjectWriterFake{},
		Tokens:        store,
		Hasher:        passwordHasherFake{},
		Tx:            txManagerFake{},
		Outbox:        &outboxFake{},
		Invalidator:   &invalidatorFake{},
		BaseURL:       "https://front.local",
		TTLMinutes:    60,
		Now:           fixedNow,
		GenerateToken: func() (string, error) { return "tok", nil },
	})

	err := svc.Perform(context.Background(), "user@test.com", "tok", "newpass")

	require.ErrorIs(t, err, passwordreset.ErrInvalidToken)
}

func TestServicePerformCurrentPasswordReuse(t *testing.T) {
	subject := authcore.Subject{
		ID:           authshared.NewSubjectID(),
		Kind:         authcore.SubjectKindUser,
		Email:        "user@test.com",
		NumericID:    10,
		PasswordHash: "same",
	}
	store := &passwordResetStoreFake{
		getByEmailFn: func(_ context.Context, email string) (authcore.PasswordResetToken, error) {
			return authcore.PasswordResetToken{
				Email:     email,
				Token:     "tok",
				CreatedAt: fixedNow(),
			}, nil
		},
	}
	invalidator := &invalidatorFake{}
	svc := passwordreset.Must(passwordreset.Options{
		Reader: subjectReaderFake{
			getByEmailFn: func(_ context.Context, _ string) (authcore.Subject, error) {
				return subject, nil
			},
		},
		Writer:        subjectWriterFake{},
		Tokens:        store,
		Hasher:        passwordHasherFake{},
		Tx:            txManagerFake{},
		Outbox:        &outboxFake{},
		Invalidator:   invalidator,
		BaseURL:       "https://front.local",
		TTLMinutes:    60,
		Now:           fixedNow,
		GenerateToken: func() (string, error) { return "tok", nil },
	})

	err := svc.Perform(context.Background(), "user@test.com", "tok", "same")

	require.ErrorIs(t, err, passwordreset.ErrPasswordIsEqualCurrentPassword)
	require.Empty(t, invalidator.invalidatedSubjectIDs)
}

func TestServicePerformSuccessInvalidatesSubjectTokens(t *testing.T) {
	subjectID := authshared.NewSubjectID()
	subject := authcore.Subject{
		ID:           subjectID,
		Kind:         authcore.SubjectKindUser,
		Email:        "user@test.com",
		NumericID:    10,
		PasswordHash: "hash:current",
	}
	store := &passwordResetStoreFake{
		getByEmailFn: func(_ context.Context, email string) (authcore.PasswordResetToken, error) {
			return authcore.PasswordResetToken{
				Email:     email,
				Token:     "tok",
				CreatedAt: fixedNow(),
			}, nil
		},
	}
	invalidator := &invalidatorFake{}
	outbox := &outboxFake{}
	svc := passwordreset.Must(passwordreset.Options{
		Reader: subjectReaderFake{
			getByEmailFn: func(_ context.Context, _ string) (authcore.Subject, error) {
				return subject, nil
			},
		},
		Writer: subjectWriterFake{
			updatePasswordFn: func(_ context.Context, got authcore.Subject, passwordHash string) error {
				require.Equal(t, subjectID, got.AuthSubjectID())
				require.Equal(t, "hash:new-pass", passwordHash)
				return nil
			},
		},
		Tokens:      store,
		Hasher:      passwordHasherFake{},
		Tx:          txManagerFake{},
		Outbox:      outbox,
		Invalidator: invalidator,
		BaseURL:     "https://front.local",
		TTLMinutes:  60,
		Now:         fixedNow,
		GenerateToken: func() (string, error) {
			return "tok", nil
		},
	})

	err := svc.Perform(context.Background(), "user@test.com", "tok", "new-pass")

	require.NoError(t, err)
	require.Equal(t, []authcore.SubjectID{subjectID}, invalidator.invalidatedSubjectIDs)
	require.Len(t, outbox.calls, 1)
	require.Contains(t, outbox.calls[0].payload, "password_reset_success")
}

func TestServicePerformUpdatePasswordFailureDoesNotInvalidate(t *testing.T) {
	subjectID := authshared.NewSubjectID()
	subject := authcore.Subject{
		ID:           subjectID,
		Kind:         authcore.SubjectKindUser,
		Email:        "user@test.com",
		PasswordHash: "hash:current",
	}
	store := &passwordResetStoreFake{
		getByEmailFn: func(_ context.Context, email string) (authcore.PasswordResetToken, error) {
			return authcore.PasswordResetToken{
				Email:     email,
				Token:     "tok",
				CreatedAt: fixedNow(),
			}, nil
		},
	}
	invalidator := &invalidatorFake{}
	svc := passwordreset.Must(passwordreset.Options{
		Reader: subjectReaderFake{
			getByEmailFn: func(_ context.Context, _ string) (authcore.Subject, error) {
				return subject, nil
			},
		},
		Writer: subjectWriterFake{
			updatePasswordFn: func(context.Context, authcore.Subject, string) error {
				return errors.New("update failed")
			},
		},
		Tokens:      store,
		Hasher:      passwordHasherFake{},
		Tx:          txManagerFake{},
		Outbox:      &outboxFake{},
		Invalidator: invalidator,
		BaseURL:     "https://front.local",
		TTLMinutes:  60,
		Now:         fixedNow,
		GenerateToken: func() (string, error) {
			return "tok", nil
		},
	})

	err := svc.Perform(context.Background(), "user@test.com", "tok", "new-pass")

	require.Error(t, err)
	require.Empty(t, invalidator.invalidatedSubjectIDs)
}

func fixedNow() time.Time {
	return time.Date(2026, time.April, 16, 12, 0, 0, 0, time.UTC)
}

type subjectReaderFake struct {
	getByEmailFn func(ctx context.Context, email string) (authcore.Subject, error)
}

func (f subjectReaderFake) GetByEmail(ctx context.Context, email string) (authcore.Subject, error) {
	if f.getByEmailFn != nil {
		return f.getByEmailFn(ctx, email)
	}
	return authcore.Subject{}, nil
}

type subjectWriterFake struct {
	updatePasswordFn func(ctx context.Context, subject authcore.Subject, passwordHash string) error
}

func (subjectWriterFake) CreateUser(_ context.Context, subject authcore.Subject) (authcore.Subject, error) {
	return subject, nil
}

func (f subjectWriterFake) UpdatePassword(ctx context.Context, subject authcore.Subject, passwordHash string) error {
	if f.updatePasswordFn != nil {
		return f.updatePasswordFn(ctx, subject, passwordHash)
	}
	return nil
}

type passwordResetStoreFake struct {
	upsertCalled    bool
	lastToken       authcore.PasswordResetToken
	getByEmailFn    func(ctx context.Context, email string) (authcore.PasswordResetToken, error)
	deleteByEmailFn func(ctx context.Context, email string) error
}

func (f *passwordResetStoreFake) Upsert(_ context.Context, token authcore.PasswordResetToken) error {
	f.upsertCalled = true
	f.lastToken = token
	return nil
}

func (f *passwordResetStoreFake) GetByEmail(ctx context.Context, email string) (authcore.PasswordResetToken, error) {
	if f.getByEmailFn != nil {
		return f.getByEmailFn(ctx, email)
	}
	return authcore.PasswordResetToken{}, nil
}

func (f *passwordResetStoreFake) DeleteByEmail(ctx context.Context, email string) error {
	if f.deleteByEmailFn != nil {
		return f.deleteByEmailFn(ctx, email)
	}
	return nil
}

type outboxFake struct {
	calls []outboxCall
}

type outboxCall struct {
	name        string
	payload     string
	availableAt time.Time
}

func (f *outboxFake) Put(_ context.Context, name, payload string, availableAt time.Time) (outbox.JobID, error) {
	f.calls = append(f.calls, outboxCall{
		name:        name,
		payload:     payload,
		availableAt: availableAt,
	})
	return outbox.NewJobID(), nil
}

type txManagerFake struct{}

func (txManagerFake) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type passwordHasherFake struct{}

func (passwordHasherFake) GenerateHash(password string) ([]byte, error) {
	return []byte("hash:" + password), nil
}

func (passwordHasherFake) CompareHash(passwordHash string, password string) error {
	if passwordHash == password {
		return nil
	}
	return errors.New("mismatch")
}

type invalidatorFake struct {
	invalidatedSubjectIDs []authcore.SubjectID
	err                   error
}

func (f *invalidatorFake) InvalidateAll(_ context.Context, subjectID authcore.SubjectID) error {
	f.invalidatedSubjectIDs = append(f.invalidatedSubjectIDs, subjectID)
	return f.err
}
