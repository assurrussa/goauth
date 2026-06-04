package listallroles

import (
	"github.com/assurrussa/goshared/pkg/validator"

	"github.com/assurrussa/goauth/domain/roles/model"
)

type Request struct{}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct {
	Roles           []model.Role
	Permissions     []model.Permission
	RolePermissions []model.RolePermission
	SubjectRoles    []model.SubjectRole
	RoleHierarchy   []model.RoleHierarchy
}
