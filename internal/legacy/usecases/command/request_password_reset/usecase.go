package requestpasswordreset

import (
	"context"
	"fmt"

	logger "github.com/assurrussa/gologger"
)

//go:generate toolsmocks

type passwordResetService interface {
	Request(ctx context.Context, email string) error
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
		return Response{}, fmt.Errorf("validate request: %w", err)
	}

	if err := u.passwordResetService.Request(ctx, req.Email); err != nil {
		return Response{}, fmt.Errorf("request password reset: %w", err)
	}

	return Response{Success: true}, nil
}
