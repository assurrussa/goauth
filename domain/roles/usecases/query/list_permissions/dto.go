package listpermissions

import (
	"github.com/assurrussa/goshared/pkg/validator"

	"github.com/assurrussa/goauth/domain/roles/shared"
)

type Request struct {
	Domain string `validate:"omitempty"`
	Action string `validate:"omitempty"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Permission struct {
	ID          int64                   `json:"id"`
	UUID        string                  `json:"uuid"`
	Domain      shared.PermissionDomain `json:"domain"`
	Action      shared.PermissionAction `json:"action"`
	Description *string                 `json:"description,omitempty"`
}

type Response struct {
	Permissions []Permission `json:"permissions"`
}
