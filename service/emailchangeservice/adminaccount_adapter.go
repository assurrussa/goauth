package emailchangeservice

import (
	"context"

	"github.com/assurrussa/goauth/session/adminaccount"
)

type AdminAccountAdapter[T comparable] struct {
	manager Manager[T]
}

func NewAdminAccountAdapter[T comparable](manager Manager[T]) *AdminAccountAdapter[T] {
	return &AdminAccountAdapter[T]{manager: manager}
}

func (a *AdminAccountAdapter[T]) Request(
	ctx context.Context,
	subject adminaccount.Subject[T],
	newEmail,
	clientIP string,
) error {
	return a.manager.Request(ctx, Subject[T]{
		ID:          subject.ID,
		CanonicalID: subject.CanonicalID,
		Email:       subject.Email,
		Name:        subject.Name,
	}, newEmail, clientIP)
}

func (a *AdminAccountAdapter[T]) Confirm(ctx context.Context, subject adminaccount.Subject[T], code string) (string, error) {
	return a.manager.Confirm(ctx, Subject[T]{
		ID:          subject.ID,
		CanonicalID: subject.CanonicalID,
		Email:       subject.Email,
		Name:        subject.Name,
	}, code)
}

func (a *AdminAccountAdapter[T]) GetPending(
	ctx context.Context,
	subject adminaccount.Subject[T],
) (*adminaccount.Pending, error) {
	pending, err := a.manager.GetPending(ctx, subject.ID)
	if err != nil || pending == nil {
		return nil, err
	}

	return &adminaccount.Pending{
		NewEmail:  pending.NewEmail,
		ExpiresAt: pending.ExpiresAt,
	}, nil
}
