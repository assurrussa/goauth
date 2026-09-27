//nolint:nolintlint,revive // standard project naming pattern
package shared

import (
	"fmt"
	"strings"
)

const separator = ":"

type (
	PermissionDomain string
	PermissionAction string
)

func (p PermissionDomain) String() string {
	return string(p)
}

func (p PermissionAction) String() string {
	return string(p)
}

type PermissionKey struct {
	Domain PermissionDomain
	Action PermissionAction
}

func NewPermissionKey(domain PermissionDomain, action PermissionAction) PermissionKey {
	return PermissionKey{
		Domain: domain,
		Action: action,
	}
}

func (k PermissionKey) String() string {
	return fmt.Sprintf("%s%s%s", k.Domain, separator, k.Action)
}

func ParsePermissionKey(value string) PermissionKey {
	parts := strings.SplitN(value, separator, 2)
	if len(parts) != 2 {
		return PermissionKey{}
	}

	return PermissionKey{
		Domain: PermissionDomain(parts[0]),
		Action: PermissionAction(parts[1]),
	}
}

func (k PermissionKey) IsZero() bool {
	return k.Domain == "" || k.Action == ""
}

const (
	PermissionDomainRoles       PermissionDomain = "roles"
	PermissionDomainPermissions PermissionDomain = "permissions"
	PermissionDomainAdmins      PermissionDomain = "admins"
	PermissionDomainDashboard   PermissionDomain = "dashboard"
	PermissionDomainOperations  PermissionDomain = "operations"
	PermissionDomainUsers       PermissionDomain = "users"
	PermissionDomainUploads     PermissionDomain = "uploads"
	PermissionDomainQueues      PermissionDomain = "queues"
)

const (
	PermissionActionRead   PermissionAction = "read"
	PermissionActionCreate PermissionAction = "create"
	PermissionActionUpdate PermissionAction = "update"
	PermissionActionDelete PermissionAction = "delete"
	PermissionActionAssign PermissionAction = "assign"
	PermissionActionSync   PermissionAction = "sync"
)
