package listrolepermissions

import (
	"github.com/assurrussa/goshared/pkg/validator"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/shared"
)

type Request struct {
	RoleID int64 `validate:"gt=0"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Permission struct {
	Domain      shared.PermissionDomain `json:"domain"`
	Action      shared.PermissionAction `json:"action"`
	Description *string                 `json:"description,omitempty"`
}

type Response struct {
	Permissions []Permission `json:"permissions"`
}
