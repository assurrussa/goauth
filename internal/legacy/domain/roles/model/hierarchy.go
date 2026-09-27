package model

import "time"

type RoleHierarchy struct {
	ParentRoleID int64     `json:"parentRoleId" db:"parent_role_id"`
	ChildRoleID  int64     `json:"childRoleId" db:"child_role_id"`
	CreatedAt    time.Time `json:"createdAt" db:"created_at"`
}
