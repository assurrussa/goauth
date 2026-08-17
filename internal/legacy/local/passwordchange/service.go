package passwordchange

import (
	"context"
	"errors"
	"fmt"
	"time"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/infrastructure/notify"
	notificationsjob "github.com/assurrussa/goauth/internal/legacy/infrastructure/notify/notifications"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

var (
	ErrInvalidSubject                 = errors.New("invalid subject")
	ErrInvalidCurrentPassword         = errors.New("invalid current password")
	ErrPasswordIsEqualCurrentPassword = errors.New("new password is equal current password")
)

type OutboxPutter interface {
	Put(ctx context.Context, name, payload string, availableAt time.Time) (outbox.JobID, error)
}

type Options struct {
	Lookup authcore.SubjectLookup
	Writer authcore.SubjectWriter
	Hasher authcore.PasswordHasher
	Tx     authcore.TxManager
	Outbox OutboxPutter
	Now    func() time.Time
}

type Service struct {
	lookup authcore.SubjectLookup
	writer authcore.SubjectWriter
	hasher authcore.PasswordHasher
	tx     authcore.TxManager
	outbox OutboxPutter
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
		hasher: opts.Hasher,
		tx:     opts.Tx,
		outbox: opts.Outbox,
		now:    now,
	}, nil
}

func (s *Service) Change(ctx context.Context, subjectID authcore.SubjectID, currentPassword, newPassword string) error {
	if subjectID.IsZero() {
		return ErrInvalidSubject
	}

	subject, err := s.lookup.GetByID(ctx, subjectID)
	if err != nil {
		return fmt.Errorf("get subject by id: %w", err)
	}
	if subject.IsZero() {
		return ErrInvalidSubject
	}

	if err := s.hasher.CompareHash(subject.PasswordHash, currentPassword); err != nil {
		return ErrInvalidCurrentPassword
	}
	if err := s.hasher.CompareHash(subject.PasswordHash, newPassword); err == nil {
		return ErrPasswordIsEqualCurrentPassword
	}

	hash, err := s.hasher.GenerateHash(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	changeFn := func(ctx context.Context) error {
		if err := s.writer.UpdatePassword(ctx, subject, string(hash)); err != nil {
			return fmt.Errorf("update password: %w", err)
		}
		return s.enqueueSuccessNotification(ctx, subject)
	}

	if s.tx != nil && s.outbox != nil {
		if err := s.tx.RunInTx(ctx, changeFn); err != nil {
			return fmt.Errorf("change password transaction: %w", err)
		}

		return nil
	}

	return changeFn(ctx)
}

func (s *Service) enqueueSuccessNotification(ctx context.Context, subject authcore.Subject) error {
	if s.outbox == nil || subject.Email == "" {
		return nil
	}

	payload := notificationsjob.Payload{
		Channel:  notify.ChannelEmail,
		To:       subject.Email,
		Title:    "Пароль успешно изменен",
		Template: "password_change_success",
		Metadata: map[string]any{
			"email": subject.Email,
		},
	}
	data, err := notificationsjob.MarshalPayload(payload)
	if err != nil {
		return fmt.Errorf("marshal password change payload: %w", err)
	}
	if _, err := s.outbox.Put(ctx, notificationsjob.JobName, data, s.now()); err != nil {
		return fmt.Errorf("outbox password change put: %w", err)
	}

	return nil
}
