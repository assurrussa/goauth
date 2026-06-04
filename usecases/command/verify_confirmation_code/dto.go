package verifyconfirmationcode

import (
	"fmt"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/core"
	"github.com/assurrussa/goauth/shared"
)

type Request struct {
	ID        sharedtypes.RequestID   `validate:"required"`
	SubjectID authcore.SubjectID      `validate:"required"`
	CodeType  shared.ConfirmationType `validate:"required"`
	Code      string                  `validate:"required,min=3,max=20"`
}

func (r Request) Validate() error {
	if err := validator.Validator.Struct(r); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if err := r.CodeType.ValidateFor(shared.ConfirmationActionVerify); err != nil {
		return fmt.Errorf("invalid code type: %w", err)
	}

	return nil
}

type Response struct {
	Success   bool
	Message   string
	Confirmed bool
	Reason    string `json:"reason,omitempty"`
}
