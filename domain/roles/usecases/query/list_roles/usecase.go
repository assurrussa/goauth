package listroles

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth/domain/roles/model"
	"github.com/assurrussa/goauth/domain/roles/repository"
)

var ErrNilService = errors.New("list roles query: nil service")

type Service interface {
	ListRoles(ctx context.Context, filter repository.RoleFilter) ([]model.Role, error)
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

	filter := repository.RoleFilter{
		IDs:        req.IDs,
		Slugs:      req.normalizedSlugs(),
		IncludeSys: req.IncludeSystem,
		Search:     req.Search,
		Pagination: repository.Pagination{
			Limit:  req.Limit,
			Offset: req.Offset,
		},
	}

	roles, err := u.service.ListRoles(ctx, filter)
	if err != nil {
		return Response{}, fmt.Errorf("list roles: %w", err)
	}

	resp := Response{
		Roles: make([]Role, 0, len(roles)),
	}

	for _, role := range roles {
		resp.Roles = append(resp.Roles, Role{
			ID:       role.ID,
			UUID:     role.UUID,
			Slug:     role.Slug,
			Name:     role.Name,
			IsSystem: role.IsSystem,
		})
	}

	return resp, nil
}
