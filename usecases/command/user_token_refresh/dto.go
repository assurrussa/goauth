package usertokenrefresh

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/core"
)

type Request struct {
	ID           sharedtypes.RequestID `validate:"required"`
	RefreshToken string                `validate:"required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct {
	SubjectID        authcore.SubjectID
	Domain           string
	AccessToken      string
	RefreshToken     string
	ExpiresIn        int64
	ExpiresRefreshIn int64
}
