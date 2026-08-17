package assignsubjectroles

import (
	"github.com/assurrussa/goshared/pkg/validator"
)

type Request struct {
	SubjectID string  `validate:"required"`
	RoleIDs   []int64 `validate:"dive,gt=0"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct {
	Assigned int `json:"assigned"`
}
