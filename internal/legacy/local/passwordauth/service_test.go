package passwordauth_test

import (
	"context"
	"errors"
	"testing"

	passwordhasher "github.com/assurrussa/goshared/services/password_hasher"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/local/passwordauth"
)

type subjectReaderStub struct {
	subject authcore.Subject
	err     error
}

func (s subjectReaderStub) GetByEmail(_ context.Context, _ string) (authcore.Subject, error) {
	return s.subject, s.err
}

func TestAuthenticateSuccess(t *testing.T) {
	t.Parallel()

	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174000")
	hasher := passwordhasher.NewArgon2idService(passwordhasher.WithArgon2idMemory(8*1024), passwordhasher.WithArgon2idIterations(1))
	hash, err := hasher.GenerateHash("password")
	require.NoError(t, err)

	svc := passwordauth.Must(passwordauth.Options{
		Reader: subjectReaderStub{subject: authcore.Subject{
			ID:           subjectID,
			Kind:         authcore.SubjectKindAccount,
			Email:        "test@example.com", //nolint:goconst // autofix
			PasswordHash: string(hash),
		}},
		Credentials: authcore.StaticSubjectCredentials{},
		Hasher:      hasher,
	})

	subject, err := svc.Authenticate(context.Background(), authcore.Credential{
		Email:    "test@example.com",
		Password: "password", //nolint:goconst // autofix
	})
	require.NoError(t, err)
	require.Equal(t, subjectID, subject.ID)
}

func TestAuthenticateInvalidCredentials(t *testing.T) {
	t.Parallel()

	hasher := passwordhasher.NewArgon2idService(passwordhasher.WithArgon2idMemory(8*1024), passwordhasher.WithArgon2idIterations(1))
	hash, err := hasher.GenerateHash("password")
	require.NoError(t, err)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174001")

	svc := passwordauth.Must(passwordauth.Options{
		Reader:      subjectReaderStub{subject: authcore.Subject{ID: subjectID, Email: "test@example.com", PasswordHash: string(hash)}},
		Credentials: authcore.StaticSubjectCredentials{},
		Hasher:      hasher,
	})

	_, err = svc.Authenticate(context.Background(), authcore.Credential{Email: "", Password: "password"})
	require.ErrorIs(t, err, passwordauth.ErrInvalidCredentials)

	_, err = svc.Authenticate(context.Background(), authcore.Credential{Email: "test@example.com", Password: "wrong"})
	require.ErrorIs(t, err, passwordauth.ErrInvalidCredentials)

	svc = passwordauth.Must(passwordauth.Options{
		Reader:      subjectReaderStub{},
		Credentials: authcore.StaticSubjectCredentials{},
		Hasher:      hasher,
	})

	_, err = svc.Authenticate(context.Background(), authcore.Credential{Email: "missing@example.com", Password: "password"})
	require.ErrorIs(t, err, passwordauth.ErrInvalidCredentials)
}

func TestAuthenticateReaderError(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("boom")

	svc := passwordauth.Must(passwordauth.Options{
		Reader:      subjectReaderStub{err: expectedErr},
		Credentials: authcore.StaticSubjectCredentials{},
		Hasher:      passwordhasher.NewArgon2idService(passwordhasher.WithArgon2idMemory(8*1024), passwordhasher.WithArgon2idIterations(1)),
	})

	_, err := svc.Authenticate(context.Background(), authcore.Credential{
		Email:    "test@example.com",
		Password: "password",
	})
	require.ErrorIs(t, err, expectedErr)
}
