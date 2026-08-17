package userlogout

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

type Request struct {
	ID           sharedtypes.RequestID `validate:"required"`
	SubjectID    authcore.SubjectID    `validate:"required"`
	RefreshToken string                `validate:"required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct{}
