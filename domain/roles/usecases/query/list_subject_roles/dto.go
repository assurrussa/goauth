package listsubjectroles

import (
	"github.com/assurrussa/goshared/pkg/validator"

	"github.com/assurrussa/goauth/domain/roles/model"
)

type Request struct {
	SubjectID string `validate:"required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct {
	Roles []model.Role `json:"roles"`
}
