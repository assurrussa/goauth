package model

import (
	"time"

	"github.com/assurrussa/goauth/domain/roles/shared"
)

type Permission struct {
	ID          int64                   `json:"id" db:"id"`
	UUID        string                  `json:"uuid" db:"uuid"`
	Domain      shared.PermissionDomain `json:"domain" db:"domain"`
	Action      shared.PermissionAction `json:"action" db:"action"`
	Description *string                 `json:"description" db:"description"`
	CreatedAt   time.Time               `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time               `json:"updatedAt" db:"updated_at"`
}

func (p Permission) Key() string {
	return p.Domain.String() + ":" + p.Action.String()
}

type PermissionWithRole struct {
	RoleID int64 `json:"roleId" db:"role_id"`
	Permission
}
