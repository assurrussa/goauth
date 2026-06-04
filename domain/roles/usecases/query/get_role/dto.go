package getrole

import (
	"github.com/assurrussa/goshared/pkg/validator"

	"github.com/assurrussa/goauth/domain/roles/shared"
)

type Request struct {
	RoleID             int64 `validate:"gt=0"`
	IncludePermissions bool
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
	ID          int64        `json:"id"`
	UUID        string       `json:"uuid"`
	Slug        string       `json:"slug"`
	Name        string       `json:"name"`
	IsSystem    bool         `json:"isSystem"`
	Description *string      `json:"description,omitempty"`
	Permissions []Permission `json:"permissions,omitempty"`
}
