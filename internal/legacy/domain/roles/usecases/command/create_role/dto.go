package createrole

import (
	"fmt"
	"strings"

	"github.com/assurrussa/goshared/pkg/validator"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/shared"
)

type Request struct {
	Slug           string  `validate:"required"`
	Name           string  `validate:"required"`
	Description    *string `validate:"omitempty"`
	IsSystem       bool
	PermissionKeys []string `validate:"dive,required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

func (r Request) permissionKeyModels() ([]shared.PermissionKey, error) {
	if len(r.PermissionKeys) == 0 {
		return nil, nil
	}

	keys := make([]shared.PermissionKey, 0, len(r.PermissionKeys))
	for _, raw := range r.PermissionKeys {
		key := shared.ParsePermissionKey(strings.TrimSpace(raw))
		if key.IsZero() {
			return nil, fmt.Errorf("invalid permission key: %s", raw)
		}

		keys = append(keys, key)
	}

	return keys, nil
}

type Response struct {
	RoleID int64  `json:"roleId"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
}
