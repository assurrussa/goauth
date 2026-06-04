package performpasswordreset

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goshared/pkg/logger"

	"github.com/assurrussa/goauth/local/passwordreset"
)

//go:generate toolsmocks

var (
	ErrInvalidRequest                 = errors.New("invalid request")
	ErrInvalidToken                   = passwordreset.ErrInvalidToken
	ErrInvalidPasswordConfirm         = errors.New("invalid password confirm")
	ErrPasswordIsEqualCurrentPassword = passwordreset.ErrPasswordIsEqualCurrentPassword
)

type passwordResetService interface {
	Perform(ctx context.Context, email, token, password string) error
}

//go:generate options-gen -out-filename=usecase_options.gen.go -from-struct=Options
type Options struct {
	logger               logger.Logger        `option:"mandatory" validate:"required"`
	passwordResetService passwordResetService `option:"mandatory" validate:"required"`
}

type UseCase struct{ Options }

func Must(opts Options) *UseCase {
	uc, err := New(opts)
	if err != nil {
		panic(err)
	}
	return uc
}

func New(opts Options) (*UseCase, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validate options: %w", err)
	}
	return &UseCase{Options: opts}, nil
}

func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, errors.Join(ErrInvalidRequest, err)
	}

	if err := u.passwordResetService.Perform(ctx, req.Email, req.Token, req.Password); err != nil {
		return Response{}, fmt.Errorf("perform password reset: %w", err)
	}

	return Response{Success: true}, nil
}
