package updaterole

import (
	"fmt"
	"strings"

	"github.com/assurrussa/goshared/pkg/validator"

	"github.com/assurrussa/goauth/domain/roles/shared"
)

type Request struct {
	ID             int64     `validate:"gt=0"`
	Slug           string    `validate:"required"`
	Name           string    `validate:"required"`
	Description    *string   `validate:"omitempty"`
	IsSystem       *bool     `validate:"omitempty"`
	PermissionKeys *[]string `validate:"omitempty,dive,required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

func (r Request) permissionKeyModels() ([]shared.PermissionKey, bool, error) {
	if r.PermissionKeys == nil {
		return nil, false, nil
	}

	rawKeys := *r.PermissionKeys
	if len(rawKeys) == 0 {
		empty := make([]shared.PermissionKey, 0)
		return empty, true, nil
	}

	keys := make([]shared.PermissionKey, 0, len(rawKeys))
	for _, raw := range rawKeys {
		key := shared.ParsePermissionKey(strings.TrimSpace(raw))
		if key.IsZero() {
			return nil, false, fmt.Errorf("invalid permission key: %s", raw)
		}

		keys = append(keys, key)
	}

	return keys, true, nil
}

type Response struct {
	RoleID   int64  `json:"roleId"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	IsSystem bool   `json:"isSystem"`
}
