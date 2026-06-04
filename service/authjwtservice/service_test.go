package authjwtservice_test

import (
	"context"
	"testing"
	"time"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	passwordhasher "github.com/assurrussa/goshared/services/password_hasher"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/core"
	"github.com/assurrussa/goauth/service/authjwtservice"
	authshared "github.com/assurrussa/goauth/shared"
)

type subjectStoreStub struct {
	byID    map[authcore.SubjectID]authcore.Subject
	byEmail map[string]authcore.Subject
}

func newSubjectStoreStub() *subjectStoreStub {
	return &subjectStoreStub{
		byID:    make(map[authcore.SubjectID]authcore.Subject),
		byEmail: make(map[string]authcore.Subject),
	}
}

func (s *subjectStoreStub) GetByEmail(_ context.Context, email string) (authcore.Subject, error) {
	return s.byEmail[email], nil
}

func (s *subjectStoreStub) GetByID(_ context.Context, subjectID authcore.SubjectID) (authcore.Subject, error) {
	return s.byID[subjectID], nil
}

func (s *subjectStoreStub) CreateUser(_ context.Context, subject authcore.Subject) (authcore.Subject, error) {
	if subject.PublicID.IsZero() {
		subject.PublicID = sharedtypes.NewUserID()
	}
	if subject.Kind == authcore.SubjectKindUnknown {
		subject.Kind = authcore.SubjectKindAccount
	}
	if subject.ID.IsZero() {
		subject.ID = authshared.NewSubjectID()
	}
	s.byID[subject.ID] = subject
	s.byEmail[subject.Email] = subject
	return subject, nil
}

func (s *subjectStoreStub) UpdatePassword(_ context.Context, subject authcore.Subject, passwordHash string) error {
	current := s.byID[subject.AuthSubjectID()]
	current.PasswordHash = passwordHash
	current.PasswordVersion++
	s.byID[current.AuthSubjectID()] = current
	s.byEmail[current.Email] = current
	return nil
}

type refreshTokenStoreStub struct {
	byToken map[string]authcore.AuthSession
}

func newRefreshTokenStoreStub() *refreshTokenStoreStub {
	return &refreshTokenStoreStub{byToken: make(map[string]authcore.AuthSession)}
}

func (s *refreshTokenStoreStub) Save(_ context.Context, session authcore.AuthSession) error {
	s.byToken[session.Token] = session
	return nil
}

func (s *refreshTokenStoreStub) Get(_ context.Context, token string) (authcore.AuthSession, error) {
	session, ok := s.byToken[token]
	if !ok {
		return authcore.AuthSession{}, authcore.ErrSessionNotFound
	}
	return session, nil
}

func (s *refreshTokenStoreStub) GetBySessionID(_ context.Context, sessionID int64) (authcore.AuthSession, error) {
	for _, session := range s.byToken {
		if session.NumericID == sessionID {
			return session, nil
		}
	}
	return authcore.AuthSession{}, authcore.ErrSessionNotFound
}

func (s *refreshTokenStoreStub) ListBySubject(_ context.Context, subjectID authcore.SubjectID) ([]authcore.AuthSession, error) {
	result := make([]authcore.AuthSession, 0, len(s.byToken))
	for _, session := range s.byToken {
		if session.SubjectID == subjectID {
			result = append(result, session)
		}
	}
	return result, nil
}

func (s *refreshTokenStoreStub) Delete(_ context.Context, subjectID authcore.SubjectID, token string) (bool, error) {
	session, ok := s.byToken[token]
	if !ok || session.SubjectID != subjectID {
		return false, nil
	}
	delete(s.byToken, token)
	return true, nil
}

func (s *refreshTokenStoreStub) DeleteAll(_ context.Context, subjectID authcore.SubjectID) (int64, error) {
	var deleted int64
	for token, session := range s.byToken {
		if session.SubjectID == subjectID {
			delete(s.byToken, token)
			deleted++
		}
	}
	return deleted, nil
}

func (s *refreshTokenStoreStub) DeleteAllExcept(
	_ context.Context,
	subjectID authcore.SubjectID,
	keepToken string,
) (int64, error) {
	var deleted int64
	for token, session := range s.byToken {
		if session.SubjectID == subjectID && token != keepToken {
			delete(s.byToken, token)
			deleted++
		}
	}
	return deleted, nil
}

func (s *refreshTokenStoreStub) DeleteBySessionID(
	_ context.Context,
	subjectID authcore.SubjectID,
	sessionID int64,
) (bool, error) {
	for token, session := range s.byToken {
		if session.SubjectID == subjectID && session.NumericID == sessionID {
			delete(s.byToken, token)
			return true, nil
		}
	}
	return false, nil
}

func (s *refreshTokenStoreStub) Ban(
	_ context.Context,
	subjectID authcore.SubjectID,
	sessionID int64,
	reason string,
) (bool, error) {
	for token, session := range s.byToken {
		if session.SubjectID == subjectID && session.NumericID == sessionID {
			now := time.Now().UTC()
			session.BannedAt = &now
			session.Reason = &reason
			s.byToken[token] = session
			return true, nil
		}
	}
	return false, nil
}

func (s *refreshTokenStoreStub) Unban(_ context.Context, subjectID authcore.SubjectID, sessionID int64) (bool, error) {
	for token, session := range s.byToken {
		if session.SubjectID == subjectID && session.NumericID == sessionID {
			session.BannedAt = nil
			session.Reason = nil
			s.byToken[token] = session
			return true, nil
		}
	}
	return false, nil
}

func (s *refreshTokenStoreStub) IsBanned(_ context.Context, token string) (bool, error) {
	session, ok := s.byToken[token]
	if !ok {
		return false, nil
	}
	return session.BannedAt != nil, nil
}

type txStub struct{}

func (txStub) RunInTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type jwtStub struct {
	domain string
	next   *authcore.TokenPair
}

func (j jwtStub) GenerateTokenPair(subject authcore.Subject) (*authcore.TokenPair, error) {
	pair := *j.next
	pair.SubjectID = subject.AuthSubjectID()
	pair.Kind = subject.Kind
	return &pair, nil
}

type profileProvisionerStub struct {
	subjects []authcore.Subject
	profile  authcore.Profile
}

func (p *profileProvisionerStub) ProvisionForSubject(
	_ context.Context,
	subject authcore.Subject,
) (authcore.Profile, error) {
	p.subjects = append(p.subjects, subject)
	return p.profile, nil
}

func TestMustPanicsOnMissingDeps(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() {
		authjwtservice.Must(authjwtservice.NewOptions(nil, nil, nil, nil, nil, nil, nil))
	})
}

func TestLoginIssuesAndPersistsTokenPair(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subjects := newSubjectStoreStub()
	tokens := newRefreshTokenStoreStub()
	hasher := passwordhasher.NewService()
	hash, err := hasher.GenerateHash("secret")
	require.NoError(t, err)

	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	subject := authcore.Subject{
		ID:              subjectID,
		Kind:            authcore.SubjectKindUser,
		PublicID:        userID,
		Email:           "user@example.com",
		PasswordHash:    string(hash),
		PasswordVersion: 3,
	}
	subjects.byID[subject.ID] = subject
	subjects.byEmail[subject.Email] = subject

	service := authjwtservice.Must(authjwtservice.NewOptions(
		subjects,
		subjects,
		subjects,
		tokens,
		jwtStub{
			domain: ".example.test",
			next: &authcore.TokenPair{
				Domain:           ".example.test",
				AccessToken:      "access-token",
				RefreshToken:     "refresh-token",
				ExpiresIn:        60,
				ExpiresRefreshIn: 3600,
			},
		},
		hasher,
		txStub{},
	))

	pair, err := service.Login(ctx, subject.Email, "secret")
	require.NoError(t, err)
	require.Equal(t, subject.ID, pair.SubjectID)
	require.Equal(t, "refresh-token", pair.RefreshToken)

	session, err := tokens.Get(ctx, "refresh-token")
	require.NoError(t, err)
	require.Equal(t, subject.ID, session.SubjectID)
	require.Equal(t, int64(3), session.PasswordVersion)
}

func TestLoginProvisionsProfileBeforeIssuingTokenPair(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subjects := newSubjectStoreStub()
	tokens := newRefreshTokenStoreStub()
	hasher := passwordhasher.NewService()
	hash, err := hasher.GenerateHash("secret")
	require.NoError(t, err)

	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	subject := authcore.Subject{
		ID:              subjectID,
		Kind:            authcore.SubjectKindAdmin,
		PublicID:        userID,
		Email:           "admin@example.com",
		PasswordHash:    string(hash),
		PasswordVersion: 7,
	}
	subjects.byID[subject.ID] = subject
	subjects.byEmail[subject.Email] = subject
	provisioner := &profileProvisionerStub{
		profile: authcore.Profile{
			ID:        42,
			SubjectID: subjectID,
			PublicID:  userID,
			Email:     "admin@example.com",
			Name:      "Admin User",
		},
	}

	service := authjwtservice.Must(authjwtservice.NewOptions(
		subjects,
		subjects,
		subjects,
		tokens,
		jwtStub{
			domain: ".example.test",
			next: &authcore.TokenPair{
				Domain:           ".example.test",
				AccessToken:      "access-token",
				RefreshToken:     "refresh-token",
				ExpiresIn:        60,
				ExpiresRefreshIn: 3600,
			},
		},
		hasher,
		txStub{},
		authjwtservice.WithProfileProvisioner(provisioner),
	))

	pair, err := service.Login(ctx, subject.Email, "secret")
	require.NoError(t, err)
	require.Equal(t, subject.ID, pair.SubjectID)
	require.Equal(t, "refresh-token", pair.RefreshToken)
	require.Len(t, provisioner.subjects, 1)
	require.Equal(t, subject.ID, provisioner.subjects[0].AuthSubjectID())
	require.Equal(t, subject.PublicID, provisioner.subjects[0].PublicID)

	session, err := tokens.Get(ctx, "refresh-token")
	require.NoError(t, err)
	require.Equal(t, subject.ID, session.SubjectID)
	require.Equal(t, int64(7), session.PasswordVersion)
}

func TestRegisterPreservesProvidedName(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subjects := newSubjectStoreStub()
	tokens := newRefreshTokenStoreStub()
	hasher := passwordhasher.NewService()

	service := authjwtservice.Must(authjwtservice.NewOptions(
		subjects,
		subjects,
		subjects,
		tokens,
		jwtStub{
			domain: ".example.test",
			next: &authcore.TokenPair{
				Domain:           ".example.test",
				AccessToken:      "access-token",
				RefreshToken:     "refresh-token",
				ExpiresIn:        60,
				ExpiresRefreshIn: 3600,
			},
		},
		hasher,
		txStub{},
	))

	subject, err := service.Register(ctx, "user@example.com", "secret", "secret", "Amir")
	require.NoError(t, err)
	require.Equal(t, "Amir", subject.Name)
	require.Equal(t, "Amir", subjects.byEmail["user@example.com"].Name)
}

func TestRefreshRotatesStoredSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subjects := newSubjectStoreStub()
	tokens := newRefreshTokenStoreStub()
	hasher := passwordhasher.NewService()

	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	subject := authcore.Subject{
		ID:              subjectID,
		Kind:            authcore.SubjectKindUser,
		PublicID:        userID,
		Email:           "user@example.com",
		PasswordVersion: 5,
	}
	subjects.byID[subject.ID] = subject
	subjects.byEmail[subject.Email] = subject
	tokens.byToken["old-refresh"] = authcore.AuthSession{
		ID:              "17",
		SubjectID:       subject.ID,
		Kind:            authcore.SubjectKindUser,
		Token:           "old-refresh",
		NumericID:       17,
		PasswordVersion: 5,
		CreatedAt:       time.Now().Add(-time.Minute),
		ExpiresAt:       time.Now().Add(time.Hour),
	}

	service := authjwtservice.Must(authjwtservice.NewOptions(
		subjects,
		subjects,
		subjects,
		tokens,
		jwtStub{
			domain: ".example.test",
			next: &authcore.TokenPair{
				Domain:           ".example.test",
				AccessToken:      "new-access",
				RefreshToken:     "new-refresh",
				ExpiresIn:        60,
				ExpiresRefreshIn: 3600,
			},
		},
		hasher,
		txStub{},
	))

	pair, err := service.RefreshToken(ctx, "old-refresh")
	require.NoError(t, err)
	require.Equal(t, "new-refresh", pair.RefreshToken)

	_, err = tokens.Get(ctx, "old-refresh")
	require.ErrorIs(t, err, authcore.ErrSessionNotFound)

	newSession, err := tokens.Get(ctx, "new-refresh")
	require.NoError(t, err)
	require.Equal(t, subject.ID, newSession.SubjectID)
	require.Equal(t, int64(5), newSession.PasswordVersion)
}
