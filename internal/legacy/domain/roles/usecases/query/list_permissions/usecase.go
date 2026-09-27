package listpermissions

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
	"github.com/assurrussa/goauth/internal/legacy/domain/roles/repository"
)

var ErrNilService = errors.New("list permissions query: nil service")

type Service interface {
	ListPermissions(ctx context.Context, filter repository.PermissionFilter) ([]model.Permission, error)
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

	filter := repository.PermissionFilter{
		Domain: req.Domain,
		Action: req.Action,
	}

	perms, err := u.service.ListPermissions(ctx, filter)
	if err != nil {
		return Response{}, fmt.Errorf("list permissions: %w", err)
	}

	resp := Response{
		Permissions: make([]Permission, 0, len(perms)),
	}

	for _, perm := range perms {
		resp.Permissions = append(resp.Permissions, Permission{
			ID:          perm.ID,
			UUID:        perm.UUID,
			Domain:      perm.Domain,
			Action:      perm.Action,
			Description: perm.Description,
		})
	}

	return resp, nil
}
