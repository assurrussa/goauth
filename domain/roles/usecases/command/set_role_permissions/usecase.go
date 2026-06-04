package setrolepermissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth/domain/roles/shared"
)

var ErrNilService = errors.New("set role permissions usecase: nil service")

type Service interface {
	SetRolePermissions(ctx context.Context, roleID int64, keys []shared.PermissionKey) error
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

	keys, err := req.permissionKeyModels()
	if err != nil {
		return Response{}, err
	}

	if err := u.service.SetRolePermissions(ctx, req.RoleID, keys); err != nil {
		return Response{}, fmt.Errorf("set role permissions: %w", err)
	}

	return Response{Total: len(keys)}, nil
}
