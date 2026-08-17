package requestpasswordreset

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"
)

type Request struct {
	ID    sharedtypes.RequestID `validate:"required"`
	Email string                `validate:"required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct {
	Success bool
}
