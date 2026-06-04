package updaterole

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth/domain/roles/model"
	rolesservice "github.com/assurrussa/goauth/domain/roles/service/roles"
	"github.com/assurrussa/goauth/domain/roles/shared"
)

var ErrNilService = errors.New("update role usecase: nil service")

type Service interface {
	UpdateRole(ctx context.Context, input rolesservice.UpdateRoleInput) (*model.Role, error)
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

	var permissions *[]shared.PermissionKey
	if keys, replace, err := req.permissionKeyModels(); err != nil {
		return Response{}, err
	} else if replace {
		permissions = &keys
	}

	role, err := u.service.UpdateRole(ctx, rolesservice.UpdateRoleInput{
		ID:          req.ID,
		Slug:        req.Slug,
		Name:        req.Name,
		Description: req.Description,
		IsSystem:    req.IsSystem,
		Permissions: permissions,
	})
	if err != nil {
		return Response{}, fmt.Errorf("update role: %w", err)
	}
	if role == nil {
		return Response{}, errors.New("update role: service returned nil role")
	}

	return Response{
		RoleID:   role.ID,
		Slug:     role.Slug,
		Name:     role.Name,
		IsSystem: role.IsSystem,
	}, nil
}
