package setrolepermissions

import (
	"fmt"
	"strings"

	"github.com/assurrussa/goshared/pkg/validator"

	"github.com/assurrussa/goauth/domain/roles/shared"
)

type Request struct {
	RoleID         int64    `validate:"gt=0"`
	PermissionKeys []string `validate:"dive,required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

func (r Request) permissionKeyModels() ([]shared.PermissionKey, error) {
	if len(r.PermissionKeys) == 0 {
		return []shared.PermissionKey{}, nil
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
	Total int `json:"total"`
}
