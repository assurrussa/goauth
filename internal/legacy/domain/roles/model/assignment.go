package model

import "time"

type RolePermission struct {
	RoleID       int64     `json:"roleId" db:"role_id"`
	PermissionID int64     `json:"permissionId" db:"permission_id"`
	CreatedAt    time.Time `json:"createdAt" db:"created_at"`
}

type SubjectRole struct {
	SubjectID string    `json:"subjectId" db:"subject_id"`
	RoleID    int64     `json:"roleId" db:"role_id"`
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
}
