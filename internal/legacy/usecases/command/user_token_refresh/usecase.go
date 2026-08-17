package usertokenrefresh

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
	RefreshToken(ctx context.Context, refreshTokenString string) (*authcore.TokenPair, error)
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
		return &UseCase{}, fmt.Errorf("error create new usercase: %w", err)
	}

	return &UseCase{Options: opts}, nil
}

func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, fmt.Errorf("validate request: %w", errors.Join(ErrInvalidRequest, err))
	}

	tokenPair, err := u.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return Response{}, fmt.Errorf("register user: %w", err)
	}

	return Response{
		SubjectID:        tokenPair.SubjectID,
		Domain:           tokenPair.Domain,
		AccessToken:      tokenPair.AccessToken,
		RefreshToken:     tokenPair.RefreshToken,
		ExpiresIn:        tokenPair.ExpiresIn,
		ExpiresRefreshIn: tokenPair.ExpiresRefreshIn,
	}, nil
}
