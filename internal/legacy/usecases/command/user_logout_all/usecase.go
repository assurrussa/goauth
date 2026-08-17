package userlogoutall

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goshared/pkg/logger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

//go:generate toolsmocks

var ErrInvalidRequest = errors.New("invalid request")

type authService interface {
	DeleteUserRefreshTokensExcept(ctx context.Context, subjectID authcore.SubjectID, exceptToken string) (int64, error)
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
		panic(fmt.Errorf("fatal userlogoutall usecase: %w", err))
	}

	return useCase
}

func New(opts Options) (*UseCase, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("error creating new usecase: %w", err)
	}

	return &UseCase{Options: opts}, nil
}

func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, fmt.Errorf("validate request: %w", errors.Join(ErrInvalidRequest, err))
	}

	// Delete all refresh tokens for this user except the current session
	count, err := u.authService.DeleteUserRefreshTokensExcept(ctx, req.SubjectID, req.CurrentSession)
	if err != nil {
		return Response{}, fmt.Errorf("delete user refresh tokens: %w", err)
	}

	return Response{
		TokensDeleted: count,
	}, nil
}
