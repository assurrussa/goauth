package usertokenban

import (
	"context"
	"fmt"

	logger "github.com/assurrussa/gologger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

//go:generate toolsmocks

type authService interface {
	BanToken(ctx context.Context, subjectID authcore.SubjectID, tokenID int64, reason string) (bool, error)
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

	success, err := u.authService.BanToken(ctx, req.SubjectID, req.TokenID, req.Reason)
	if err != nil {
		return Response{}, fmt.Errorf("ban token: %w", err)
	}

	return Response{
		Success: success,
	}, nil
}
