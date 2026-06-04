package assignsubjectroles

import (
	"context"
	"errors"
	"fmt"
)

var ErrNilService = errors.New("assign subject roles usecase: nil service")

type Service interface {
	AssignRolesToSubject(ctx context.Context, subjectID string, roleIDs []int64) error
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

	if err := u.service.AssignRolesToSubject(ctx, req.SubjectID, req.RoleIDs); err != nil {
		return Response{}, fmt.Errorf("assign roles: %w", err)
	}

	return Response{Assigned: len(req.RoleIDs)}, nil
}
