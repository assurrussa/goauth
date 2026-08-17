package listsubjectroles

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
)

var ErrNilService = errors.New("list subject roles query: nil service")

type Service interface {
	ListSubjectRoles(ctx context.Context, subjectID string) ([]model.Role, error)
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

	roles, err := u.service.ListSubjectRoles(ctx, req.SubjectID)
	if err != nil {
		return Response{}, fmt.Errorf("list subject roles: %w", err)
	}

	return Response{
		Roles: roles,
	}, nil
}
