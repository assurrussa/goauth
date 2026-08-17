package usertokenrevoke

import (
	"context"
	"fmt"

	"github.com/assurrussa/goshared/pkg/logger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

//go:generate toolsmocks

type authService interface {
	RevokeTokenByID(ctx context.Context, subjectID authcore.SubjectID, tokenID int64) (bool, error)
}

//go:generate options-gen -out-filename=usecase_options.gen.go -from-struct=Options
type Options struct {
	logger      logger.Logger `option:"mandatory" validate:"required"`
	authService authService   `option:"mandatory" validate:"required"`
}

type UseCase struct {
	Options
}

func Must(opts Options) *UseCase {
	useCase, err := New(opts)
	if err != nil {
		panic(err)
	}
	return useCase
}

func New(opts Options) (*UseCase, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validate options: %w", err)
	}

	return &UseCase{
		Options: opts,
	}, nil
}

func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, fmt.Errorf("validate request: %w", err)
	}

	success, err := u.authService.RevokeTokenByID(ctx, req.SubjectID, req.TokenID)
	if err != nil {
		return Response{}, fmt.Errorf("revoke token: %w", err)
	}

	return Response{
		Success: success,
	}, nil
}
