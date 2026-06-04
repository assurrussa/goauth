package getrole

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth/domain/roles/model"
)

var ErrNilService = errors.New("get role query: nil service")

type Service interface {
	GetRole(ctx context.Context, id int64) (*model.Role, error)
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

	role, err := u.service.GetRole(ctx, req.RoleID)
	if err != nil {
		return Response{}, fmt.Errorf("get role: %w", err)
	}
	if role == nil {
		return Response{}, errors.New("role not found")
	}

	resp := Response{
		ID:       role.ID,
		UUID:     role.UUID,
		Slug:     role.Slug,
		Name:     role.Name,
		IsSystem: role.IsSystem,
	}
	if role.Description.Valid {
		resp.Description = &role.Description.String
	}

	if req.IncludePermissions {
		perms, err := u.service.ListRolePermissions(ctx, role.ID)
		if err != nil {
			return Response{}, fmt.Errorf("list permissions: %w", err)
		}

		resp.Permissions = make([]Permission, 0, len(perms))
		for _, perm := range perms {
			resp.Permissions = append(resp.Permissions, Permission{
				Domain:      perm.Domain,
				Action:      perm.Action,
				Description: perm.Description,
			})
		}
	}

	return resp, nil
}
