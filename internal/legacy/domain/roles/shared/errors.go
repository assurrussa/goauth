//nolint:nolintlint,revive // standard project naming pattern
package shared

import "errors"

var (
	ErrRoleNotFound        = errors.New("role not found")
	ErrPermissionNotFound  = errors.New("permission not found")
	ErrAssignmentNotFound  = errors.New("assignment not found")
	ErrInvalidPermission   = errors.New("invalid permission key")
	ErrInvalidRoleID       = errors.New("invalid role id")
	ErrInvalidRoleSlug     = errors.New("invalid role slug")
	ErrInvalidSubjectID    = errors.New("invalid subject id")
	ErrSystemRoleProtected = errors.New("system role protected")
)
