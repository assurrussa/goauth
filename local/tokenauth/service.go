package tokenauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authcore "github.com/assurrussa/goauth/core"
)

var (
	ErrInvalidPasswordConfirm = errors.New("invalid password confirmation")
	ErrInvalidToken           = errors.New("invalid token")
	ErrInvalidSubjectOrToken  = errors.New("invalid subject or token")
	ErrExpiredToken           = errors.New("token expired")
	ErrBannedToken            = errors.New("banned token")
	ErrCannotCurrentToken     = errors.New("cannot revoke the current session token")
	ErrAnotherSubjectToken    = errors.New("token does not belong to the subject")
)

type Options struct {
	Lookup authcore.SubjectLookup
	Writer authcore.SubjectWriter
	Tokens authcore.RefreshTokenStore
	Issuer authcore.TokenIssuer
	Tx     authcore.TxManager
	Hasher authcore.PasswordHasher
	Now    func() time.Time
}

type Service struct {
	lookup authcore.SubjectLookup
	writer authcore.SubjectWriter
	tokens authcore.RefreshTokenStore
	issuer authcore.TokenIssuer
	tx     authcore.TxManager
	hasher authcore.PasswordHasher
	now    func() time.Time
}

func Must(opts Options) *Service {
	svc, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("panic: %w", err))
	}

	return svc
}

func New(opts Options) (*Service, error) {
	switch {
	case opts.Lookup == nil:
		return nil, errors.New("lookup is required")
	case opts.Writer == nil:
		return nil, errors.New("writer is required")
	case opts.Tokens == nil:
		return nil, errors.New("tokens are required")
	case opts.Issuer == nil:
		return nil, errors.New("issuer is required")
	case opts.Tx == nil:
		return nil, errors.New("tx is required")
	case opts.Hasher == nil:
		return nil, errors.New("hasher is required")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &Service{
		lookup: opts.Lookup,
		writer: opts.Writer,
		tokens: opts.Tokens,
		issuer: opts.Issuer,
		tx:     opts.Tx,
		hasher: opts.Hasher,
		now:    now,
	}, nil
}

func (s *Service) Register(ctx context.Context, email, password, confirmPassword, name string) (authcore.Subject, error) {
	email = strings.TrimSpace(email)
	if email == "" || password == "" || password != confirmPassword {
		return authcore.Subject{}, ErrInvalidPasswordConfirm
	}

	hashedPassword, err := s.hasher.GenerateHash(password)
	if err != nil {
		return authcore.Subject{}, fmt.Errorf("hash password: %w", err)
	}

	subject, err := s.writer.CreateUser(ctx, authcore.Subject{
		Kind:         authcore.SubjectKindAccount,
		Email:        email,
		Name:         strings.TrimSpace(name),
		PasswordHash: string(hashedPassword),
	})
	if err != nil {
		return authcore.Subject{}, fmt.Errorf("create user: %w", err)
	}

	return subject, nil
}

func (s *Service) IssueTokenPair(ctx context.Context, subject authcore.Subject) (*authcore.TokenPair, error) {
	if subject.IsZero() || subject.CanonicalID() == "" {
		return nil, ErrInvalidSubjectOrToken
	}

	pair, err := s.issuer.GenerateTokenPair(subject)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	if err := s.tokens.Save(ctx, s.sessionForPair(subject, pair)); err != nil {
		return nil, fmt.Errorf("save refresh token: %w", err)
	}

	return pair, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (*authcore.TokenPair, error) {
	if refreshToken == "" {
		return nil, ErrInvalidToken
	}

	session, err := s.tokens.Get(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	if session.IsZero() || session.SubjectID.IsZero() {
		return nil, ErrInvalidToken
	}

	if s.now().After(session.ExpiresAt) {
		if _, err := s.tokens.Delete(ctx, session.SubjectID, refreshToken); err != nil {
			return nil, fmt.Errorf("delete refresh token in expired: %w", errors.Join(err, ErrExpiredToken))
		}

		return nil, ErrExpiredToken
	}

	if session.BannedAt != nil {
		return nil, ErrBannedToken
	}

	subject, err := s.lookup.GetByID(ctx, session.SubjectID)
	if err != nil {
		return nil, fmt.Errorf("get subject by id: %w", err)
	}
	if subject.IsZero() || subject.PasswordVersion != session.PasswordVersion {
		return nil, ErrInvalidToken
	}

	pair, err := s.issuer.GenerateTokenPair(subject)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	newSession := s.sessionForPair(subject, pair)
	if err := s.tx.RunInTx(ctx, func(ctx context.Context) error {
		if _, err := s.tokens.Delete(ctx, session.SubjectID, refreshToken); err != nil {
			return fmt.Errorf("delete: %w", err)
		}

		if err := s.tokens.Save(ctx, newSession); err != nil {
			return fmt.Errorf("save: %w", err)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("save refresh token: %w", err)
	}

	return pair, nil
}

func (s *Service) Delete(ctx context.Context, subjectID authcore.SubjectID, refreshToken string) error {
	if subjectID.IsZero() || refreshToken == "" {
		return ErrInvalidSubjectOrToken
	}

	if _, err := s.tokens.Delete(ctx, subjectID, refreshToken); err != nil {
		return fmt.Errorf("delete refresh token: %w", err)
	}

	return nil
}

func (s *Service) DeleteAll(ctx context.Context, subjectID authcore.SubjectID) error {
	if subjectID.IsZero() {
		return ErrInvalidSubjectOrToken
	}

	if _, err := s.tokens.DeleteAll(ctx, subjectID); err != nil {
		return fmt.Errorf("delete user refresh tokens: %w", err)
	}

	return nil
}

func (s *Service) DeleteAllExcept(ctx context.Context, subjectID authcore.SubjectID, keepToken string) (int64, error) {
	if subjectID.IsZero() || keepToken == "" {
		return 0, ErrInvalidSubjectOrToken
	}

	count, err := s.tokens.DeleteAllExcept(ctx, subjectID, keepToken)
	if err != nil {
		return 0, fmt.Errorf("delete user refresh tokens except current: %w", err)
	}

	return count, nil
}

func (s *Service) ListBySubject(ctx context.Context, subjectID authcore.SubjectID) ([]authcore.AuthSession, error) {
	if subjectID.IsZero() {
		return nil, ErrInvalidSubjectOrToken
	}

	sessions, err := s.tokens.ListBySubject(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("get user refresh tokens: %w", err)
	}

	return sessions, nil
}

func (s *Service) Revoke(
	ctx context.Context,
	subjectID authcore.SubjectID,
	tokenToRevoke string,
	currentToken string,
) (bool, error) {
	if subjectID.IsZero() || tokenToRevoke == "" || currentToken == "" {
		return false, ErrInvalidSubjectOrToken
	}

	if s.isTokenRelatedToCurrentSession(tokenToRevoke, currentToken) {
		return false, ErrCannotCurrentToken
	}

	deleted, err := s.tokens.Delete(ctx, subjectID, tokenToRevoke)
	if err != nil {
		return false, fmt.Errorf("delete refresh token: %w", err)
	}

	return deleted, nil
}

func (s *Service) RevokeBySessionID(ctx context.Context, subjectID authcore.SubjectID, sessionID int64) (bool, error) {
	if subjectID.IsZero() || sessionID < 1 {
		return false, ErrInvalidSubjectOrToken
	}

	session, err := s.tokens.GetBySessionID(ctx, sessionID)
	if err != nil {
		return false, fmt.Errorf("get token: %w", err)
	}
	if session.SubjectID != subjectID {
		return false, ErrAnotherSubjectToken
	}

	deleted, err := s.tokens.DeleteBySessionID(ctx, subjectID, sessionID)
	if err != nil {
		return false, fmt.Errorf("delete refresh token: %w", err)
	}

	return deleted, nil
}

func (s *Service) Ban(ctx context.Context, subjectID authcore.SubjectID, sessionID int64, reason string) (bool, error) {
	if subjectID.IsZero() || sessionID < 1 || reason == "" {
		return false, ErrInvalidSubjectOrToken
	}

	ok, err := s.tokens.Ban(ctx, subjectID, sessionID, reason)
	if err != nil {
		return false, fmt.Errorf("ban token: %w", err)
	}

	return ok, nil
}

func (s *Service) CheckIfBanned(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, ErrInvalidToken
	}

	isBanned, err := s.tokens.IsBanned(ctx, token)
	if err != nil {
		return false, fmt.Errorf("check if token is banned: %w", err)
	}

	return isBanned, nil
}

func (s *Service) Unban(ctx context.Context, subjectID authcore.SubjectID, sessionID int64) (bool, error) {
	if subjectID.IsZero() || sessionID < 1 {
		return false, ErrInvalidSubjectOrToken
	}

	ok, err := s.tokens.Unban(ctx, subjectID, sessionID)
	if err != nil {
		return false, fmt.Errorf("unban token: %w", err)
	}

	return ok, nil
}

func (s *Service) sessionForPair(subject authcore.Subject, pair *authcore.TokenPair) authcore.AuthSession {
	return authcore.AuthSession{
		SubjectID:       subject.AuthSubjectID(),
		Kind:            subject.Kind,
		Token:           pair.RefreshToken,
		PasswordVersion: subject.PasswordVersion,
		ExpiresAt:       s.now().Add(time.Duration(pair.ExpiresRefreshIn) * time.Second),
	}
}

func (s *Service) isTokenRelatedToCurrentSession(token, currentToken string) bool {
	return token == currentToken
}
