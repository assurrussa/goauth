package userlogout

import (
	"context"
	"errors"
	"fmt"

	logger "github.com/assurrussa/gologger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

//go:generate toolsmocks

var ErrInvalidRequest = errors.New("invalid request")

type authService interface {
	DeleteRefreshToken(ctx context.Context, subjectID authcore.SubjectID, refreshToken string) error
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
		panic(fmt.Errorf("fatal pgsqlinit usecase: %w", err))
	}

	return useCase
}

func New(opts Options) (*UseCase, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("error create new usercase: %w", err)
	}

	return &UseCase{Options: opts}, nil
}

func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, fmt.Errorf("validate request: %w", errors.Join(ErrInvalidRequest, err))
	}

	err := u.authService.DeleteRefreshToken(ctx, req.SubjectID, req.RefreshToken)
	if err != nil {
		return Response{}, fmt.Errorf("delete refresh token: %w", err)
	}

	return Response{}, nil
}
