package passwordreset

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	generate_token "github.com/assurrussa/goauth/internal/generate_token"
	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/infrastructure/notify"
	notificationsjob "github.com/assurrussa/goauth/internal/legacy/infrastructure/notify/notifications"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

var (
	ErrInvalidToken                   = errors.New("invalid token")
	ErrPasswordIsEqualCurrentPassword = errors.New("new password is equal current password")
)

type OutboxPutter interface {
	Put(ctx context.Context, name, payload string, availableAt time.Time) (outbox.JobID, error)
}

type Invalidator interface {
	InvalidateAll(ctx context.Context, subjectID authcore.SubjectID) error
}

type Options struct {
	Reader        authcore.SubjectReader
	Writer        authcore.SubjectWriter
	Tokens        authcore.PasswordResetStore
	Hasher        authcore.PasswordHasher
	Tx            authcore.TxManager
	Outbox        OutboxPutter
	Invalidator   Invalidator
	BaseURL       string
	TTLMinutes    int
	Now           func() time.Time
	GenerateToken func() (string, error)
}

type Service struct {
	reader        authcore.SubjectReader
	writer        authcore.SubjectWriter
	tokens        authcore.PasswordResetStore
	hasher        authcore.PasswordHasher
	tx            authcore.TxManager
	outbox        OutboxPutter
	invalidator   Invalidator
	baseURL       string
	ttlMinutes    int
	now           func() time.Time
	generateToken func() (string, error)
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
	case opts.Writer == nil:
		return nil, errors.New("writer is required")
	case opts.Tokens == nil:
		return nil, errors.New("tokens are required")
	case opts.Hasher == nil:
		return nil, errors.New("hasher is required")
	case opts.Tx == nil:
		return nil, errors.New("tx is required")
	case opts.Outbox == nil:
		return nil, errors.New("outbox is required")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	generateToken := opts.GenerateToken
	if generateToken == nil {
		generateToken = generate_token.GenerateToken
	}

	return &Service{
		reader:        opts.Reader,
		writer:        opts.Writer,
		tokens:        opts.Tokens,
		hasher:        opts.Hasher,
		tx:            opts.Tx,
		outbox:        opts.Outbox,
		invalidator:   opts.Invalidator,
		baseURL:       opts.BaseURL,
		ttlMinutes:    opts.TTLMinutes,
		now:           now,
		generateToken: generateToken,
	}, nil
}

func (s *Service) Request(ctx context.Context, email string) error {
	subject, err := s.reader.GetByEmail(ctx, strings.TrimSpace(email))
	if err != nil {
		return fmt.Errorf("get user: %w", err)
	}
	if subject.IsZero() || subject.Email == "" {
		return nil
	}

	token, err := s.generateToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	tm := s.now()
	return s.tx.RunInTx(ctx, func(ctx context.Context) error {
		if err := s.tokens.Upsert(ctx, authcore.PasswordResetToken{
			Email:     subject.Email,
			SubjectID: subject.AuthSubjectID(),
			Token:     token,
			CreatedAt: tm,
		}); err != nil {
			return fmt.Errorf("upsert token: %w", err)
		}

		resetURL := s.resetURL(subject.Email, token)
		payload := notificationsjob.Payload{
			Channel:  notify.ChannelEmail,
			To:       subject.Email,
			Title:    "Восстановление пароля",
			Template: "password_reset",
			Metadata: map[string]any{
				"reset_link":      resetURL,
				"expires_minutes": s.ttlMinutes,
			},
		}
		data, err := notificationsjob.MarshalPayload(payload)
		if err != nil {
			return fmt.Errorf("marshal payload: %w", err)
		}
		if _, err := s.outbox.Put(ctx, notificationsjob.JobName, data, tm); err != nil {
			return fmt.Errorf("outbox put: %w", err)
		}

		return nil
	})
}

func (s *Service) Perform(ctx context.Context, email, token, password string) error {
	record, err := s.tokens.GetByEmail(ctx, email)
	if err != nil || record.Email == "" {
		return ErrInvalidToken
	}
	if record.Token != token {
		return ErrInvalidToken
	}
	if s.ttlMinutes > 0 && s.now().Sub(record.CreatedAt) > time.Duration(s.ttlMinutes)*time.Minute {
		return ErrInvalidToken
	}

	subject, err := s.reader.GetByEmail(ctx, record.Email)
	if err != nil || subject.IsZero() {
		return fmt.Errorf("get subject by email: %w", errors.Join(ErrInvalidToken, err))
	}
	if err := s.hasher.CompareHash(subject.PasswordHash, password); err == nil {
		return ErrPasswordIsEqualCurrentPassword
	}

	hash, err := s.hasher.GenerateHash(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	if err := s.tx.RunInTx(ctx, func(ctx context.Context) error {
		if err := s.writer.UpdatePassword(ctx, subject, string(hash)); err != nil {
			return fmt.Errorf("update user: %w", err)
		}
		if err := s.tokens.DeleteByEmail(ctx, record.Email); err != nil {
			return fmt.Errorf("delete reset token: %w", err)
		}
		if s.invalidator != nil {
			if err := s.invalidator.InvalidateAll(ctx, subject.AuthSubjectID()); err != nil {
				return fmt.Errorf("invalidate auth artifacts: %w", err)
			}
		}
		payload := notificationsjob.Payload{
			Channel:  notify.ChannelEmail,
			To:       subject.Email,
			Title:    "Пароль успешно изменен",
			Template: "password_reset_success",
			Metadata: map[string]any{
				"email": subject.Email,
			},
		}
		data, err := notificationsjob.MarshalPayload(payload)
		if err != nil {
			return fmt.Errorf("marshal success payload: %w", err)
		}
		if _, err := s.outbox.Put(ctx, notificationsjob.JobName, data, s.now()); err != nil {
			return fmt.Errorf("outbox success put: %w", err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("handle RunInTx: %w", err)
	}

	return nil
}

func (s *Service) resetURL(email, token string) string {
	base := strings.TrimRight(s.baseURL, "/") + "/reset-password"
	q := url.Values{}
	q.Set("token", token)
	q.Set("email", email)

	return base + "?" + q.Encode()
}
