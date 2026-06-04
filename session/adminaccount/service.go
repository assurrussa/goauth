package adminaccount

import (
	"context"
	"errors"
	"fmt"
	"time"

	authcore "github.com/assurrussa/goauth/core"
)

type PasswordResetManager interface {
	Request(ctx context.Context, email string) error
	Perform(ctx context.Context, email, token, password string) error
}

type PasswordChangeManager interface {
	Change(ctx context.Context, subjectID authcore.SubjectID, currentPassword, newPassword string) error
}

type TxManager interface {
	RunInTx(ctx context.Context, fn func(ctx context.Context) error) error
}

type Subject[T comparable] struct {
	ID          T
	CanonicalID authcore.SubjectID
	Email       string
	Name        string
}

type Pending struct {
	NewEmail  string    `json:"newEmail"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type EmailChangeManager[T comparable] interface {
	Request(ctx context.Context, subject Subject[T], newEmail, clientIP string) error
	Confirm(ctx context.Context, subject Subject[T], code string) (string, error)
	GetPending(ctx context.Context, subject Subject[T]) (*Pending, error)
}

type Options struct {
	Lookup       authcore.SubjectLookup
	Reset        PasswordResetManager
	Change       PasswordChangeManager
	EmailChanges EmailChangeManager[int64]
	Tx           TxManager
}

type Service struct {
	lookup       authcore.SubjectLookup
	reset        PasswordResetManager
	change       PasswordChangeManager
	emailChanges EmailChangeManager[int64]
	tx           TxManager
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
	case opts.Reset == nil:
		return nil, errors.New("reset is required")
	case opts.Change == nil:
		return nil, errors.New("change is required")
	case opts.EmailChanges == nil:
		return nil, errors.New("email changes are required")
	case opts.Tx == nil:
		return nil, errors.New("tx is required")
	}

	return &Service{
		lookup:       opts.Lookup,
		reset:        opts.Reset,
		change:       opts.Change,
		emailChanges: opts.EmailChanges,
		tx:           opts.Tx,
	}, nil
}

func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	return s.reset.Request(ctx, email)
}

func (s *Service) PerformPasswordReset(ctx context.Context, email, token, password string) error {
	return s.reset.Perform(ctx, email, token, password)
}

func (s *Service) ChangePassword(
	ctx context.Context,
	subjectID authcore.SubjectID,
	currentPassword string,
	newPassword string,
) error {
	return s.change.Change(ctx, subjectID, currentPassword, newPassword)
}

func (s *Service) RequestEmailChange(ctx context.Context, subjectID authcore.SubjectID, newEmail, clientIP string) error {
	subject, err := s.emailSubject(ctx, subjectID)
	if err != nil {
		return err
	}

	return s.tx.RunInTx(ctx, func(ctx context.Context) error {
		return s.emailChanges.Request(ctx, subject, newEmail, clientIP)
	})
}

func (s *Service) ConfirmEmailChange(ctx context.Context, subjectID authcore.SubjectID, code string) (string, error) {
	subject, err := s.emailSubject(ctx, subjectID)
	if err != nil {
		return "", err
	}

	var newEmail string
	err = s.tx.RunInTx(ctx, func(ctx context.Context) error {
		var err error
		newEmail, err = s.emailChanges.Confirm(ctx, subject, code)
		return err
	})
	if err != nil {
		return "", err
	}

	return newEmail, nil
}

func (s *Service) GetPendingEmailChange(ctx context.Context, subjectID authcore.SubjectID) (*Pending, error) {
	subject, err := s.emailSubject(ctx, subjectID)
	if err != nil {
		return nil, err
	}

	return s.emailChanges.GetPending(ctx, subject)
}

func (s *Service) emailSubject(ctx context.Context, subjectID authcore.SubjectID) (Subject[int64], error) {
	subject, err := s.lookup.GetByID(ctx, subjectID)
	if err != nil {
		return Subject[int64]{}, fmt.Errorf("get subject by id: %w", err)
	}
	if subject.IsZero() || subject.NumericID <= 0 {
		return Subject[int64]{}, fmt.Errorf("get subject by id: %w", errors.New("invalid subject"))
	}

	return Subject[int64]{
		ID:          subject.NumericID,
		CanonicalID: subject.AuthSubjectID(),
		Email:       subject.Email,
		Name:        subject.Name,
	}, nil
}
