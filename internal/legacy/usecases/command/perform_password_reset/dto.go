package performpasswordreset

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"
)

type Request struct {
	ID              sharedtypes.RequestID `validate:"required"`
	Email           string                `validate:"required"`
	Token           string                `validate:"required"`
	Password        string                `validate:"required"`
	ConfirmPassword string                `validate:"required"`
}

func (r Request) Validate() error {
	if err := validator.Validator.Struct(r); err != nil {
		return err
	}

	if r.Password != r.ConfirmPassword {
		return ErrInvalidPasswordConfirm
	}

	return nil
}

type Response struct {
	Success bool
}
