package rcucacheguard

import (
	"context"
	"fmt"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
	listallroles "github.com/assurrussa/goauth/internal/legacy/domain/roles/usecases/query/list_all_roles"
)

// LoadData Обновить данные конфигурации.
func LoadData(rolesAllUseCase rolesAllUseCase) func(context.Context) (map[string]Data, error) {
	return func(ctx context.Context) (map[string]Data, error) {
		resp, err := rolesAllUseCase.Handle(ctx, listallroles.Request{})
		if err != nil {
			return nil, fmt.Errorf("error handling rolesAllUseCase.Handle: %w", err)
		}

		dataEnabled := Data{Enabled: true}
		data := Data{
			Enabled:         dataEnabled.Enabled,
			Roles:           make(map[int64]model.Role, len(resp.Roles)),
			Permissions:     make(map[int64]model.Permission),
			RolePermissions: make(map[int64]map[int64]model.RolePermission),
			RoleHierarchy:   make(map[int64]map[int64]model.RoleHierarchy),
			SubjectRole:     make(map[string]map[int64]model.SubjectRole),
		}

		for _, val := range resp.Roles {
			data.Roles[val.ID] = val
		}

		for _, val := range resp.Permissions {
			data.Permissions[val.ID] = val
		}

		for _, val := range resp.RolePermissions {
			vals, ok := data.RolePermissions[val.RoleID]
			if !ok {
				vals = make(map[int64]model.RolePermission)
			}
			vals[val.PermissionID] = val
			data.RolePermissions[val.RoleID] = vals
		}

		for _, val := range resp.RoleHierarchy {
			vals, ok := data.RoleHierarchy[val.ParentRoleID]
			if !ok {
				vals = make(map[int64]model.RoleHierarchy)
			}
			vals[val.ChildRoleID] = val
			data.RoleHierarchy[val.ParentRoleID] = vals
		}

		for _, val := range resp.SubjectRoles {
			vals, ok := data.SubjectRole[val.SubjectID]
			if !ok {
				vals = make(map[int64]model.SubjectRole)
			}
			vals[val.RoleID] = val
			data.SubjectRole[val.SubjectID] = vals
		}

		return map[string]Data{
			cacheKeyEnabled: dataEnabled,
			cacheKeyAll:     data,
		}, nil
	}
}
