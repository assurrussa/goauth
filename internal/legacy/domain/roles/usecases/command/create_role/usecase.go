package createrole

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
	rolesservice "github.com/assurrussa/goauth/internal/legacy/domain/roles/service/roles"
)

var ErrNilService = errors.New("create role usecase: nil service")

type Service interface {
	CreateRole(ctx context.Context, input rolesservice.CreateRoleInput) (*model.Role, error)
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

	role, err := u.service.CreateRole(ctx, rolesservice.CreateRoleInput{
		Slug:        req.Slug,
		Name:        req.Name,
		Description: req.Description,
		IsSystem:    req.IsSystem,
		Permissions: keys,
	})
	if err != nil {
		return Response{}, fmt.Errorf("create role: %w", err)
	}
	if role == nil {
		return Response{}, errors.New("create role: service returned nil role")
	}

	return Response{
		RoleID: role.ID,
		Slug:   role.Slug,
		Name:   role.Name,
	}, nil
}
