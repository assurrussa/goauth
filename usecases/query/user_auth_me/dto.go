package userauthme

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/core"
)

type Request struct {
	ID        sharedtypes.RequestID `validate:"required"`
	SubjectID authcore.SubjectID    `validate:"required"`
	Token     string                `validate:"required"`
	Version   int64
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct {
	Profile authcore.Profile
}
