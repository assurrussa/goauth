package emailchange

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	confirmationcode "github.com/assurrussa/goauth/internal/confirmationcode"
	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/infrastructure/notify"
	notificationsjob "github.com/assurrussa/goauth/internal/legacy/infrastructure/notify/notifications"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

var (
	ErrSameEmail    = errors.New("email is the same as current")
	ErrEmailInUse   = errors.New("email already in use")
	ErrInvalidEmail = errors.New("invalid email")
	ErrInvalidCode  = errors.New("invalid confirmation code")
	ErrCodeExpired  = errors.New("confirmation code expired")
	ErrMaxAttempts  = errors.New("confirmation code attempts exceeded")
	ErrNotFound     = errors.New("email change request not found")
	ErrWaitResend   = errors.New("wait before resend confirmation code")
)

const (
	defaultTTL         = 15 * time.Minute
	defaultMaxAttempts = 5
	defaultResendDelay = time.Minute
)

type Request struct {
	OldEmail  string
	NewEmail  string
	Code      string
	Attempts  int
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Pending struct {
	NewEmail  string    `json:"newEmail"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Store interface {
	Upsert(ctx context.Context, subjectID string, req Request) error
	Get(ctx context.Context, subjectID string, forUpdate bool) (Request, error)
	IncrementAttempts(ctx context.Context, subjectID string) error
	Delete(ctx context.Context, subjectID string) error
}

type EmailRepository interface {
	GetByEmail(ctx context.Context, email string) (authcore.Subject, error)
	UpdateEmail(ctx context.Context, subjectID, email string) error
	MarkEmailConfirmed(ctx context.Context, subjectID string, confirmedAt time.Time) error
}

type OutboxPutter interface {
	Put(ctx context.Context, name, payload string, availableAt time.Time) (outbox.JobID, error)
}

type Options struct {
	Store       Store
	Repo        EmailRepository
	Outbox      OutboxPutter
	CodeGen     func() (string, error)
	TTL         time.Duration
	MaxAttempts int
	ResendDelay time.Duration
	Now         func() time.Time
}

type Service struct {
	store       Store
	repo        EmailRepository
	outbox      OutboxPutter
	codeGen     func() (string, error)
	ttl         time.Duration
	maxAttempts int
	resendDelay time.Duration
	now         func() time.Time
}

func New(opts Options) (*Service, error) {
	switch {
	case opts.Store == nil:
		return nil, errors.New("email change service: store is required")
	case opts.Repo == nil:
		return nil, errors.New("email change service: repo is required")
	case opts.Outbox == nil:
		return nil, errors.New("email change service: outbox is required")
	}

	if opts.CodeGen == nil {
		opts.CodeGen = confirmationcode.Generate
	}
	if opts.TTL <= 0 {
		opts.TTL = defaultTTL
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultMaxAttempts
	}
	if opts.ResendDelay <= 0 {
		opts.ResendDelay = defaultResendDelay
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	return &Service{
		store:       opts.Store,
		repo:        opts.Repo,
		outbox:      opts.Outbox,
		codeGen:     opts.CodeGen,
		ttl:         opts.TTL,
		maxAttempts: opts.MaxAttempts,
		resendDelay: opts.ResendDelay,
		now:         opts.Now,
	}, nil
}

func Must(opts Options) *Service {
	svc, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("panic: %w", err))
	}

	return svc
}

func (s *Service) Request(ctx context.Context, subject authcore.Subject, newEmail, clientIP string) error {
	subjectID := subject.CanonicalID()
	if subjectID == "" {
		return errors.New("email change: subject id is required")
	}

	oldEmail := strings.ToLower(strings.TrimSpace(subject.Email))
	if strings.TrimSpace(newEmail) == "" {
		return ErrInvalidEmail
	}

	normalized := strings.ToLower(strings.TrimSpace(newEmail))
	if strings.EqualFold(normalized, oldEmail) {
		return ErrSameEmail
	}

	existing, err := s.repo.GetByEmail(ctx, normalized)
	if err != nil {
		return fmt.Errorf("email change: lookup email: %w", err)
	}
	if !existing.IsZero() && existing.CanonicalID() != subjectID {
		return ErrEmailInUse
	}

	if req, err := s.store.Get(ctx, subjectID, false); err == nil {
		if s.now().After(req.ExpiresAt) {
			_ = s.store.Delete(ctx, subjectID)
		} else if s.now().Sub(req.UpdatedAt) < s.resendDelay {
			return ErrWaitResend
		}
	} else if !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("email change: get request: %w", err)
	}

	code, err := s.codeGen()
	if err != nil {
		return fmt.Errorf("email change: generate code: %w", err)
	}

	now := s.now()
	req := Request{
		OldEmail:  oldEmail,
		NewEmail:  normalized,
		Code:      code,
		Attempts:  0,
		ExpiresAt: now.Add(s.ttl),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.Upsert(ctx, subjectID, req); err != nil {
		return fmt.Errorf("email change: upsert request: %w", err)
	}

	payloadNew := notificationsjob.Payload{
		Channel:  notify.ChannelEmail,
		To:       normalized,
		Title:    "Подтверждение смены email",
		Template: "confirmation_code",
		Metadata: map[string]any{
			"otp":             code,
			"channel":         "Email",
			"expires_minutes": int(s.ttl.Minutes()),
		},
	}
	dataNew, err := notificationsjob.MarshalPayload(payloadNew)
	if err != nil {
		return fmt.Errorf("email change: marshal new payload: %w", err)
	}
	if _, err := s.outbox.Put(ctx, notificationsjob.JobName, dataNew, now); err != nil {
		return fmt.Errorf("email change: outbox new: %w", err)
	}

	if oldEmail != "" {
		payloadOld := notificationsjob.Payload{
			Channel:  notify.ChannelEmail,
			To:       oldEmail,
			Title:    "Попытка смены email",
			Template: "email_change_alert",
			Metadata: map[string]any{
				"OldEmail": oldEmail,
				"NewEmail": normalized,
				"IP":       clientIP,
			},
		}

		dataOld, err := notificationsjob.MarshalPayload(payloadOld)
		if err != nil {
			return fmt.Errorf("email change: marshal old payload: %w", err)
		}
		if _, err := s.outbox.Put(ctx, notificationsjob.JobName, dataOld, now); err != nil {
			return fmt.Errorf("email change: outbox old: %w", err)
		}
	}

	return nil
}

func (s *Service) Confirm(ctx context.Context, subject authcore.Subject, code string) (string, error) {
	subjectID := subject.CanonicalID()
	if subjectID == "" {
		return "", errors.New("email change: subject id is required")
	}

	normalized := confirmationcode.Normalize(code)
	if normalized == "" {
		return "", ErrInvalidCode
	}

	req, err := s.store.Get(ctx, subjectID, true)
	if err != nil {
		return "", err
	}

	now := s.now()
	if now.After(req.ExpiresAt) {
		_ = s.store.Delete(ctx, subjectID)
		return "", ErrCodeExpired
	}

	if req.Code != normalized {
		_ = s.store.IncrementAttempts(ctx, subjectID)
		if req.Attempts+1 >= s.maxAttempts {
			_ = s.store.Delete(ctx, subjectID)
			return "", ErrMaxAttempts
		}
		return "", ErrInvalidCode
	}

	if err := s.repo.UpdateEmail(ctx, subjectID, req.NewEmail); err != nil {
		return "", fmt.Errorf("email change: update email: %w", err)
	}
	if err := s.repo.MarkEmailConfirmed(ctx, subjectID, now); err != nil {
		return "", fmt.Errorf("email change: mark email confirmed: %w", err)
	}
	if err := s.store.Delete(ctx, subjectID); err != nil {
		return "", fmt.Errorf("email change: delete request: %w", err)
	}

	return req.NewEmail, nil
}

func (s *Service) GetPending(ctx context.Context, subjectID string) (*Pending, error) {
	req, err := s.store.Get(ctx, subjectID, false)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if s.now().After(req.ExpiresAt) {
		_ = s.store.Delete(ctx, subjectID)
		return nil, ErrNotFound
	}

	return &Pending{
		NewEmail:  req.NewEmail,
		ExpiresAt: req.ExpiresAt,
	}, nil
}
