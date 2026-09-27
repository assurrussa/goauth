package passwordauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Options struct {
	Reader      authcore.SubjectReader
	Credentials authcore.SubjectCredentials
	Hasher      authcore.PasswordHasher
}

type Service struct {
	reader      authcore.SubjectReader
	credentials authcore.SubjectCredentials
	hasher      authcore.PasswordHasher
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
	case opts.Reader == nil:
		return nil, errors.New("reader is required")
	case opts.Credentials == nil:
		return nil, errors.New("credentials are required")
	case opts.Hasher == nil:
		return nil, errors.New("hasher is required")
	}

	return &Service{
		reader:      opts.Reader,
		credentials: opts.Credentials,
		hasher:      opts.Hasher,
	}, nil
}

func (s *Service) Authenticate(ctx context.Context, cred authcore.Credential) (authcore.Subject, error) {
	email := strings.TrimSpace(cred.Email)
	if email == "" || cred.Password == "" {
		return authcore.Subject{}, ErrInvalidCredentials
	}

	subject, err := s.reader.GetByEmail(ctx, email)
	if err != nil {
		return authcore.Subject{}, fmt.Errorf("get subject by email: %w", err)
	}

	if subject.IsZero() {
		return authcore.Subject{}, ErrInvalidCredentials
	}

	passwordHash, err := s.credentials.GetPasswordHash(ctx, subject)
	if err != nil {
		return authcore.Subject{}, fmt.Errorf("get subject password hash: %w", err)
	}

	if passwordHash == "" {
		return authcore.Subject{}, ErrInvalidCredentials
	}

	if err := s.hasher.CompareHash(passwordHash, cred.Password); err != nil {
		return authcore.Subject{}, ErrInvalidCredentials
	}

	return subject.Clone(), nil
}
