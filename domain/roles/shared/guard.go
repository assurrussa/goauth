//nolint:nolintlint,revive // standard project naming pattern
package shared

import "slices"

const (
	SuperAdminRole   = "super_admin"
	SuperSubjectRole = SuperAdminRole
)

type PermissionGuardConfig struct {
	bypassRoles []string
}

func CreateRoles(opts ...PermissionGuardOption) []string {
	cfg := &PermissionGuardConfig{bypassRoles: []string{SuperSubjectRole}}

	for _, opt := range opts {
		opt(cfg)
	}

	return slices.Clone(cfg.bypassRoles)
}

// PermissionGuardOption configures the permission middleware.
type PermissionGuardOption func(*PermissionGuardConfig)

// WithBypassRoles allows admins with any of the provided role slugs to bypass permission checks.
func WithBypassRoles(slugs ...string) PermissionGuardOption {
	return func(cfg *PermissionGuardConfig) {
		cfg.bypassRoles = append(cfg.bypassRoles, slugs...)
	}
}
