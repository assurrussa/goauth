package usertokenban

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

// Request parameters for the user token ban use case.
type Request struct {
	ID           sharedtypes.RequestID `validate:"required"`
	SubjectID    authcore.SubjectID    `validate:"required"`
	TokenID      int64                 `validate:"required,gt=0"`
	Reason       string                `validate:"required"`
	CurrentToken string                `validate:"required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

// Response from the user token ban use case.
type Response struct {
	Success bool `json:"success"`
}
