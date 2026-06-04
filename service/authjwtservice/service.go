package authjwtservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	authcore "github.com/assurrussa/goauth/core"
	"github.com/assurrussa/goauth/local/passwordauth"
	"github.com/assurrussa/goauth/local/tokenauth"
)

//go:generate toolsmocks

var (
	ErrInvalidCredentials      = errors.New("invalid credentials")
	ErrInvalidPasswordConfirm  = tokenauth.ErrInvalidPasswordConfirm
	ErrInvalidToken            = tokenauth.ErrInvalidToken
	ErrNotFoundToken           = authcore.ErrSessionNotFound
	ErrBannedToken             = tokenauth.ErrBannedToken
	ErrInvalidSubjectIDOrToken = tokenauth.ErrInvalidSubjectOrToken
	ErrExpiredToken            = tokenauth.ErrExpiredToken
	ErrCannotCurrentToken      = tokenauth.ErrCannotCurrentToken
	ErrAnotherSubjectToken     = tokenauth.ErrAnotherSubjectToken
)

type authService interface {
	Authenticate(ctx context.Context, cred authcore.Credential) (authcore.Subject, error)
}

type Service struct {
	passwordService authService
	tokenService    *tokenauth.Service
	provisioner     authcore.ProfileProvisioner
}

func Must(opts Options) *Service {
	service, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("panic: %w", err))
	}

	return service
}

func New(opts Options) (*Service, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("invalid options: %w", err)
	}

	if opts.authService == nil {
		var err error
		opts.authService, err = passwordauth.New(passwordauth.Options{
			Reader:      opts.Reader,
			Credentials: authcore.StaticSubjectCredentials{},
			Hasher:      opts.Hasher,
		})
		if err != nil {
			return nil, fmt.Errorf("build password auth service: %w", err)
		}
	}

	tokenService, err := tokenauth.New(tokenauth.Options{
		Lookup: opts.Lookup,
		Writer: opts.Writer,
		Tokens: opts.Tokens,
		Issuer: opts.Issuer,
		Tx:     opts.Tx,
		Hasher: opts.Hasher,
	})
	if err != nil {
		return nil, fmt.Errorf("build token auth service: %w", err)
	}

	return &Service{
		passwordService: opts.authService,
		tokenService:    tokenService,
		provisioner:     opts.ProfileProvisioner,
	}, nil
}

func (s *Service) Register(ctx context.Context, email, password, confirmPassword, name string) (authcore.Subject, error) {
	return s.tokenService.Register(ctx, email, password, confirmPassword, name)
}

func (s *Service) Login(ctx context.Context, email, password string) (*authcore.TokenPair, error) {
	subject, err := s.passwordService.Authenticate(ctx, authcore.Credential{
		Email:    email,
		Password: password,
	})
	if err != nil {
		if errors.Is(err, passwordauth.ErrInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("authenticate user: %w", err)
	}
	if subject.CanonicalID() == "" {
		return nil, ErrInvalidCredentials
	}

	subject, err = s.provisionLoginProfile(ctx, subject)
	if err != nil {
		return nil, err
	}

	return s.tokenService.IssueTokenPair(ctx, subject)
}

func (s *Service) provisionLoginProfile(ctx context.Context, subject authcore.Subject) (authcore.Subject, error) {
	if s.provisioner == nil {
		return subject, nil
	}

	profile, err := s.provisioner.ProvisionForSubject(ctx, subject)
	if err != nil {
		return authcore.Subject{}, fmt.Errorf("provision login profile: %w", err)
	}

	profileSubjectID := profile.AuthSubjectID()
	if !profileSubjectID.IsZero() && profileSubjectID != subject.AuthSubjectID() {
		return authcore.Subject{}, errors.New("provision login profile: subject mismatch")
	}

	return subjectWithProfile(subject, profile), nil
}

func subjectWithProfile(subject authcore.Subject, profile authcore.Profile) authcore.Subject {
	if profile.ID == 0 && profile.PublicID.IsZero() {
		return subject
	}

	subject = subject.Clone()
	if !profile.PublicID.IsZero() {
		subject.PublicID = profile.PublicID
	}
	if profile.ID != 0 {
		subject.NumericID = profile.ID
	}
	if profile.Version != 0 {
		subject.Version = profile.Version
	}
	if subject.Name == "" {
		subject.Name = profile.Name
	}
	if subject.Username == "" && profile.Username != nil {
		subject.Username = *profile.Username
	}
	if subject.LastName == "" && profile.LastName != nil {
		subject.LastName = *profile.LastName
	}
	if subject.FatherName == "" && profile.FatherName != nil {
		subject.FatherName = *profile.FatherName
	}
	if subject.Gender == nil {
		subject.Gender = profile.Gender
	}
	if !subject.Birthday.Valid {
		subject.Birthday = profile.Birthday
	}
	if subject.Data == nil {
		subject.Data = profile.Data
	}

	return subject
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*authcore.TokenPair, error) {
	return s.tokenService.Refresh(ctx, refreshToken)
}

func (s *Service) DeleteRefreshToken(ctx context.Context, subjectID authcore.SubjectID, refreshToken string) error {
	if subjectID.IsZero() || refreshToken == "" {
		return ErrInvalidSubjectIDOrToken
	}

	return s.tokenService.Delete(ctx, subjectID, refreshToken)
}

func (s *Service) DeleteUserRefreshTokens(ctx context.Context, subjectID authcore.SubjectID) error {
	if subjectID.IsZero() {
		return ErrInvalidSubjectIDOrToken
	}

	return s.tokenService.DeleteAll(ctx, subjectID)
}

func (s *Service) DeleteUserRefreshTokensExcept(
	ctx context.Context,
	subjectID authcore.SubjectID,
	exceptToken string,
) (int64, error) {
	if subjectID.IsZero() || exceptToken == "" {
		return 0, ErrInvalidSubjectIDOrToken
	}

	return s.tokenService.DeleteAllExcept(ctx, subjectID, exceptToken)
}

type TokenInfo struct {
	ID             int64      `json:"id"`
	Token          string     `json:"token"`
	Reason         *string    `json:"reason"`
	BannedAt       *time.Time `json:"bannedAt"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	CreatedAt      time.Time  `json:"createdAt"`
	IsCurrentToken bool       `json:"isCurrentToken"`
}

func (s *Service) GetUserTokens(ctx context.Context, subjectID authcore.SubjectID, currentToken string) ([]TokenInfo, error) {
	if subjectID.IsZero() {
		return nil, ErrInvalidSubjectIDOrToken
	}

	sessions, err := s.tokenService.ListBySubject(ctx, subjectID)
	if err != nil {
		return nil, err
	}

	result := make([]TokenInfo, 0, len(sessions))
	for _, session := range sessions {
		result = append(result, TokenInfo{
			ID:             session.NumericID,
			Token:          maskToken(session.Token),
			Reason:         session.Reason,
			BannedAt:       session.BannedAt,
			ExpiresAt:      session.ExpiresAt,
			CreatedAt:      session.CreatedAt,
			IsCurrentToken: session.Token == currentToken,
		})
	}

	return result, nil
}

func (s *Service) RevokeTokenByID(ctx context.Context, subjectID authcore.SubjectID, tokenID int64) (bool, error) {
	if subjectID.IsZero() || tokenID < 1 {
		return false, ErrInvalidSubjectIDOrToken
	}

	return s.tokenService.RevokeBySessionID(ctx, subjectID, tokenID)
}

func (s *Service) BanToken(ctx context.Context, subjectID authcore.SubjectID, tokenID int64, reason string) (bool, error) {
	if subjectID.IsZero() || tokenID < 1 || reason == "" {
		return false, ErrInvalidSubjectIDOrToken
	}

	return s.tokenService.Ban(ctx, subjectID, tokenID, reason)
}

func (s *Service) CheckIfTokenIsBanned(ctx context.Context, tokenString string) (bool, error) {
	return s.tokenService.CheckIfBanned(ctx, tokenString)
}

func maskToken(token string) string {
	if len(token) <= 10 {
		return token
	}

	return token[:4] + "..." + token[len(token)-4:]
}
