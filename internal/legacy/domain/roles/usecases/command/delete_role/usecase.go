package deleterole

import (
	"context"
	"errors"
	"fmt"
)

var ErrNilService = errors.New("delete role usecase: nil service")

type Service interface {
	DeleteRole(ctx context.Context, id int64) error
}

type UseCase struct {
	service Service
}

func New(service Service) (*UseCase, error) {
	if service == nil {
		return nil, ErrNilService
	}

	return &UseCase{service: service}, nil
}

func Must(service Service) *UseCase {
	uc, err := New(service)
	if err != nil {
		panic(err)
	}
	return uc
}

func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, fmt.Errorf("validate: %w", err)
	}

	if err := u.service.DeleteRole(ctx, req.RoleID); err != nil {
		return Response{}, fmt.Errorf("delete role: %w", err)
	}

	return Response{}, nil
}
