package userregister

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

type Request struct {
	ID                sharedtypes.RequestID `validate:"required"`
	Email             string                `validate:"required|email"`
	Name              string
	Password          string `validate:"required"`
	ConfirmedPassword string `validate:"required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct {
	SubjectID authcore.SubjectID
}
