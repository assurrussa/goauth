package rolesmiddleware

import (
	"github.com/gofiber/fiber/v3"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/shared"
)

type PermissionGuard interface {
	Guard(key shared.PermissionKey, guards ...shared.PermissionGuardOption) fiber.Handler
}

func RequirePermissionGuard(
	checker PermissionGuard,
) func(
	key shared.PermissionKey,
	opts ...shared.PermissionGuardOption,
) fiber.Handler {
	return func(
		key shared.PermissionKey,
		opts ...shared.PermissionGuardOption,
	) fiber.Handler {
		return RequirePermission(checker, key, opts...)
	}
}

// RequirePermission ensures the authenticated admin has the provided permission key.
// By default, admins with the "super_admin" role bypass the check.
func RequirePermission(
	checker PermissionGuard,
	key shared.PermissionKey,
	opts ...shared.PermissionGuardOption,
) fiber.Handler {
	return checker.Guard(key, opts...)
}
