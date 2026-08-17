package listrolepermissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
)

var ErrNilService = errors.New("list role permissions query: nil service")

type Service interface {
	ListRolePermissions(ctx context.Context, roleID int64) ([]model.Permission, error)
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

	perms, err := u.service.ListRolePermissions(ctx, req.RoleID)
	if err != nil {
		return Response{}, fmt.Errorf("list role permissions: %w", err)
	}

	resp := Response{
		Permissions: make([]Permission, 0, len(perms)),
	}

	for _, perm := range perms {
		resp.Permissions = append(resp.Permissions, Permission{
			Domain:      perm.Domain,
			Action:      perm.Action,
			Description: perm.Description,
		})
	}

	return resp, nil
}
