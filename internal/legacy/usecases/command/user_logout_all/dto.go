package userlogoutall

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

// Request represents a request to log out all user sessions except the current one.
type Request struct {
	ID             sharedtypes.RequestID `validate:"required"`
	SubjectID      authcore.SubjectID    `validate:"required"`
	CurrentSession string                `validate:"required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

// Response represents the response for logging out all user sessions.
type Response struct {
	TokensDeleted int64
}
