package usertokenrevoke

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/core"
)

// Request parameters for the user token revoke use case.
type Request struct {
	ID           sharedtypes.RequestID `validate:"required"`
	SubjectID    authcore.SubjectID    `validate:"required"`
	TokenID      int64                 `validate:"required,min=1"`
	CurrentToken string                `validate:"required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

// Response from the user token revoke use case.
type Response struct {
	Success bool `json:"success"`
}
