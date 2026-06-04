package authinvalidator

import (
	"context"
	"errors"
	"fmt"

	authcore "github.com/assurrussa/goauth/core"
)

type subjectScopedStore interface {
	DeleteAll(ctx context.Context, subjectID authcore.SubjectID) (int64, error)
	DeleteAllExcept(ctx context.Context, subjectID authcore.SubjectID, keepToken string) (int64, error)
}

type KeepCurrent struct {
	RefreshToken string
	SessionToken string
}

type Options struct {
	RefreshTokens subjectScopedStore
	Sessions      subjectScopedStore
}

type Service struct {
	refreshTokens subjectScopedStore
	sessions      subjectScopedStore
}

func New(opts Options) (*Service, error) {
	return &Service{
		refreshTokens: opts.RefreshTokens,
		sessions:      opts.Sessions,
	}, nil
}

func Must(opts Options) *Service {
	svc, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("panic: %w", err))
	}

	return svc
}

func (s *Service) InvalidateAll(ctx context.Context, subjectID authcore.SubjectID) error {
	if subjectID.IsZero() {
		return errors.New("subject id is required")
	}

	return errors.Join(
		invalidateAll(ctx, s.refreshTokens, subjectID, "invalidate refresh tokens"),
		invalidateAll(ctx, s.sessions, subjectID, "invalidate sessions"),
	)
}

func (s *Service) InvalidateAllExcept(ctx context.Context, subjectID authcore.SubjectID, keep KeepCurrent) error {
	if subjectID.IsZero() {
		return errors.New("subject id is required")
	}

	return errors.Join(
		invalidateAllExcept(ctx, s.refreshTokens, subjectID, keep.RefreshToken, "invalidate refresh tokens"),
		invalidateAllExcept(ctx, s.sessions, subjectID, keep.SessionToken, "invalidate sessions"),
	)
}

func invalidateAll(ctx context.Context, store subjectScopedStore, subjectID authcore.SubjectID, action string) error {
	if store == nil {
		return nil
	}

	if _, err := store.DeleteAll(ctx, subjectID); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}

	return nil
}

func invalidateAllExcept(
	ctx context.Context,
	store subjectScopedStore,
	subjectID authcore.SubjectID,
	keepToken string,
	action string,
) error {
	if store == nil {
		return nil
	}

	if keepToken == "" {
		return invalidateAll(ctx, store, subjectID, action)
	}

	if _, err := store.DeleteAllExcept(ctx, subjectID, keepToken); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}

	return nil
}
