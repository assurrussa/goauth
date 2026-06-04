package tokenauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/core"
	"github.com/assurrussa/goauth/local/tokenauth"
	authshared "github.com/assurrussa/goauth/shared"
)

func TestServiceRegisterSuccess(t *testing.T) {
	writer := &subjectWriterFake{
		createUserFn: func(_ context.Context, subject authcore.Subject) (authcore.Subject, error) {
			require.Equal(t, "user@test.com", subject.Email)
			require.Equal(t, "Amir", subject.Name)
			require.Equal(t, "hash:newpass", subject.PasswordHash)

			subject.PublicID = sharedtypes.NewUserID()
			subject.ID = authshared.NewSubjectID()
			return subject, nil
		},
	}

	svc := tokenauth.Must(tokenauth.Options{
		Lookup: subjectLookupFake{},
		Writer: writer,
		Tokens: refreshTokenStoreFake{},
		Issuer: tokenIssuerFake{},
		Tx:     txManagerFake{},
		Hasher: passwordHasherFake{},
		Now:    fixedNow,
	})

	subject, err := svc.Register(context.Background(), "user@test.com", "newpass", "newpass", " Amir ")

	require.NoError(t, err)
	require.False(t, subject.PublicID.IsZero())
}

func TestServiceRegisterInvalidPasswordConfirm(t *testing.T) {
	svc := tokenauth.Must(tokenauth.Options{
		Lookup: subjectLookupFake{},
		Writer: subjectWriterFake{},
		Tokens: refreshTokenStoreFake{},
		Issuer: tokenIssuerFake{},
		Tx:     txManagerFake{},
		Hasher: passwordHasherFake{},
	})

	_, err := svc.Register(context.Background(), "user@test.com", "newpass", "other", "Amir")

	require.ErrorIs(t, err, tokenauth.ErrInvalidPasswordConfirm)
}

func TestServiceRefreshSuccess(t *testing.T) {
	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	subject := authcore.Subject{
		ID:              subjectID,
		Kind:            authcore.SubjectKindUser,
		PublicID:        userID,
		PasswordVersion: 7,
	}
	currentSession := authcore.AuthSession{
		SubjectID:       subject.ID,
		Kind:            authcore.SubjectKindUser,
		Token:           "old-refresh",
		PasswordVersion: 7,
		ExpiresAt:       fixedNow().Add(time.Hour),
	}

	store := &refreshTokenStoreFake{
		getFn: func(_ context.Context, token string) (authcore.AuthSession, error) {
			require.Equal(t, "old-refresh", token)
			return currentSession, nil
		},
		deleteFn: func(_ context.Context, subjectID authcore.SubjectID, token string) (bool, error) {
			require.Equal(t, subject.ID, subjectID)
			require.Equal(t, "old-refresh", token)
			return true, nil
		},
		saveFn: func(_ context.Context, session authcore.AuthSession) error {
			require.Equal(t, "new-refresh", session.Token)
			require.Equal(t, subject.PasswordVersion, session.PasswordVersion)
			return nil
		},
	}

	svc := tokenauth.Must(tokenauth.Options{
		Lookup: subjectLookupFake{
			getByIDFn: func(_ context.Context, subjectID authcore.SubjectID) (authcore.Subject, error) {
				require.Equal(t, subject.ID, subjectID)
				return subject, nil
			},
		},
		Writer: subjectWriterFake{},
		Tokens: store,
		Issuer: tokenIssuerFake{
			generateFn: func(got authcore.Subject) (*authcore.TokenPair, error) {
				require.Equal(t, subject, got)
				return &authcore.TokenPair{
					SubjectID:        subject.ID,
					Kind:             subject.Kind,
					AccessToken:      "new-access",
					RefreshToken:     "new-refresh",
					ExpiresIn:        60,
					ExpiresRefreshIn: 3600,
				}, nil
			},
		},
		Tx:     txManagerFake{},
		Hasher: passwordHasherFake{},
		Now:    fixedNow,
	})

	pair, err := svc.Refresh(context.Background(), "old-refresh")

	require.NoError(t, err)
	require.Equal(t, "new-access", pair.AccessToken)
	require.Equal(t, "new-refresh", pair.RefreshToken)
}

func TestServiceRevokeBySessionIDAnotherSubject(t *testing.T) {
	subjectID := authshared.NewSubjectID()
	otherSubjectID := authshared.NewSubjectID()

	svc := tokenauth.Must(tokenauth.Options{
		Lookup: subjectLookupFake{},
		Writer: subjectWriterFake{},
		Tokens: refreshTokenStoreFake{
			getBySessionIDFn: func(_ context.Context, _ int64) (authcore.AuthSession, error) {
				return authcore.AuthSession{
					SubjectID: otherSubjectID,
				}, nil
			},
		},
		Issuer: tokenIssuerFake{},
		Tx:     txManagerFake{},
		Hasher: passwordHasherFake{},
	})

	ok, err := svc.RevokeBySessionID(context.Background(), subjectID, 10)

	require.ErrorIs(t, err, tokenauth.ErrAnotherSubjectToken)
	require.False(t, ok)
}

func fixedNow() time.Time {
	return time.Date(2026, time.April, 16, 12, 0, 0, 0, time.UTC)
}

type subjectLookupFake struct {
	getByIDFn func(ctx context.Context, subjectID authcore.SubjectID) (authcore.Subject, error)
}

func (f subjectLookupFake) GetByID(ctx context.Context, subjectID authcore.SubjectID) (authcore.Subject, error) {
	if f.getByIDFn != nil {
		return f.getByIDFn(ctx, subjectID)
	}
	return authcore.Subject{}, nil
}

type subjectWriterFake struct {
	createUserFn     func(ctx context.Context, subject authcore.Subject) (authcore.Subject, error)
	updatePasswordFn func(ctx context.Context, subject authcore.Subject, passwordHash string) error
}

func (f subjectWriterFake) CreateUser(ctx context.Context, subject authcore.Subject) (authcore.Subject, error) {
	if f.createUserFn != nil {
		return f.createUserFn(ctx, subject)
	}
	return subject, nil
}

func (f subjectWriterFake) UpdatePassword(ctx context.Context, subject authcore.Subject, passwordHash string) error {
	if f.updatePasswordFn != nil {
		return f.updatePasswordFn(ctx, subject, passwordHash)
	}
	return nil
}

type refreshTokenStoreFake struct {
	getFn            func(ctx context.Context, token string) (authcore.AuthSession, error)
	getBySessionIDFn func(ctx context.Context, sessionID int64) (authcore.AuthSession, error)
	listFn           func(ctx context.Context, subjectID authcore.SubjectID) ([]authcore.AuthSession, error)
	saveFn           func(ctx context.Context, session authcore.AuthSession) error
	deleteFn         func(ctx context.Context, subjectID authcore.SubjectID, token string) (bool, error)
	deleteAllFn      func(ctx context.Context, subjectID authcore.SubjectID) (int64, error)
	deleteExceptFn   func(ctx context.Context, subjectID authcore.SubjectID, keepToken string) (int64, error)
	deleteByIDFn     func(ctx context.Context, subjectID authcore.SubjectID, sessionID int64) (bool, error)
	banFn            func(ctx context.Context, subjectID authcore.SubjectID, sessionID int64, reason string) (bool, error)
	unbanFn          func(ctx context.Context, subjectID authcore.SubjectID, sessionID int64) (bool, error)
	isBannedFn       func(ctx context.Context, token string) (bool, error)
}

func (f refreshTokenStoreFake) Save(ctx context.Context, session authcore.AuthSession) error {
	if f.saveFn != nil {
		return f.saveFn(ctx, session)
	}
	return nil
}

func (f refreshTokenStoreFake) Get(ctx context.Context, token string) (authcore.AuthSession, error) {
	if f.getFn != nil {
		return f.getFn(ctx, token)
	}
	return authcore.AuthSession{}, errors.New("unexpected get")
}

func (f refreshTokenStoreFake) GetBySessionID(ctx context.Context, sessionID int64) (authcore.AuthSession, error) {
	if f.getBySessionIDFn != nil {
		return f.getBySessionIDFn(ctx, sessionID)
	}
	return authcore.AuthSession{}, errors.New("unexpected get by session id")
}

func (f refreshTokenStoreFake) ListBySubject(ctx context.Context, subjectID authcore.SubjectID) ([]authcore.AuthSession, error) {
	if f.listFn != nil {
		return f.listFn(ctx, subjectID)
	}
	return nil, nil
}

func (f refreshTokenStoreFake) Delete(ctx context.Context, subjectID authcore.SubjectID, token string) (bool, error) {
	if f.deleteFn != nil {
		return f.deleteFn(ctx, subjectID, token)
	}
	return false, nil
}

func (f refreshTokenStoreFake) DeleteAll(ctx context.Context, subjectID authcore.SubjectID) (int64, error) {
	if f.deleteAllFn != nil {
		return f.deleteAllFn(ctx, subjectID)
	}
	return 0, nil
}

func (f refreshTokenStoreFake) DeleteAllExcept(ctx context.Context, subjectID authcore.SubjectID, keepToken string) (int64, error) {
	if f.deleteExceptFn != nil {
		return f.deleteExceptFn(ctx, subjectID, keepToken)
	}
	return 0, nil
}

func (f refreshTokenStoreFake) DeleteBySessionID(
	ctx context.Context,
	subjectID authcore.SubjectID,
	sessionID int64,
) (bool, error) {
	if f.deleteByIDFn != nil {
		return f.deleteByIDFn(ctx, subjectID, sessionID)
	}
	return false, nil
}

func (f refreshTokenStoreFake) Ban(
	ctx context.Context,
	subjectID authcore.SubjectID,
	sessionID int64,
	reason string,
) (bool, error) {
	if f.banFn != nil {
		return f.banFn(ctx, subjectID, sessionID, reason)
	}
	return false, nil
}

func (f refreshTokenStoreFake) Unban(ctx context.Context, subjectID authcore.SubjectID, sessionID int64) (bool, error) {
	if f.unbanFn != nil {
		return f.unbanFn(ctx, subjectID, sessionID)
	}
	return false, nil
}

func (f refreshTokenStoreFake) IsBanned(ctx context.Context, token string) (bool, error) {
	if f.isBannedFn != nil {
		return f.isBannedFn(ctx, token)
	}
	return false, nil
}

type tokenIssuerFake struct {
	generateFn func(subject authcore.Subject) (*authcore.TokenPair, error)
}

func (f tokenIssuerFake) GenerateTokenPair(subject authcore.Subject) (*authcore.TokenPair, error) {
	if f.generateFn != nil {
		return f.generateFn(subject)
	}
	return &authcore.TokenPair{}, nil
}

type txManagerFake struct{}

func (txManagerFake) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type passwordHasherFake struct {
	generateHashFn func(password string) ([]byte, error)
}

func (f passwordHasherFake) GenerateHash(password string) ([]byte, error) {
	if f.generateHashFn != nil {
		return f.generateHashFn(password)
	}
	return []byte("hash:" + password), nil
}

func (passwordHasherFake) CompareHash(passwordHash string, password string) error {
	if passwordHash == password {
		return nil
	}
	return errors.New("mismatch")
}
