package rcucacheguard

import (
	"context"
	"fmt"
	"time"

	logger "github.com/assurrussa/gologger"
	rcu2 "github.com/assurrussa/goshared/pkg/cache/rcu"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
	listallroles "github.com/assurrussa/goauth/internal/legacy/domain/roles/usecases/query/list_all_roles"
)

//go:generate toolsmocks

const (
	cacheKeyEnabled = "enabled"
	cacheKeyAll     = "all"
)

type rolesAllUseCase interface {
	Handle(ctx context.Context, req listallroles.Request) (listallroles.Response, error)
}

type Option func(*CacheService)

func WithSyncInterval(duration time.Duration) Option {
	return func(c *CacheService) {
		c.syncInterval = duration
	}
}

func WithSyncCacheInterval(duration time.Duration) Option {
	return func(c *CacheService) {
		c.syncCacheInterval = duration
	}
}

type Data struct {
	Roles           map[int64]model.Role
	Permissions     map[int64]model.Permission
	RolePermissions map[int64]map[int64]model.RolePermission
	RoleHierarchy   map[int64]map[int64]model.RoleHierarchy
	SubjectRole     map[string]map[int64]model.SubjectRole
	Enabled         bool
}

type CacheService struct {
	cache             *rcu2.Cache[string, Data]
	syncInterval      time.Duration
	syncCacheInterval time.Duration
}

func NewCache(ctx context.Context, log logger.Logger, rolesAllUseCase rolesAllUseCase, opts ...Option) (*CacheService, error) {
	c := &CacheService{
		syncInterval:      5 * time.Second,
		syncCacheInterval: 4 * time.Second,
	}

	for _, opt := range opts {
		opt(c)
	}

	c.cache = rcu2.NewCache[string, Data](
		ctx, log, LoadData(rolesAllUseCase), rcu2.WithSyncInterval[string, Data](c.syncCacheInterval),
	)
	if err := <-c.cache.WaitLoading(); err != nil {
		return nil, fmt.Errorf("configurator: failed to load configs: %w", err)
	}

	return c, nil
}

func (c *CacheService) Enabled(_ context.Context) bool {
	res, _ := c.cache.Get(cacheKeyEnabled)
	return res.Enabled
}

func (c *CacheService) EnabledWait(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)

		for {
			if c.Enabled(ctx) {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(c.syncInterval):
				continue
			}
		}
	}()

	return ch
}

func (c *CacheService) Roles() map[int64]model.Role {
	res, _ := c.cache.Get(cacheKeyAll)
	return res.Roles
}

func (c *CacheService) Permissions() map[int64]model.Permission {
	res, _ := c.cache.Get(cacheKeyAll)
	return res.Permissions
}

func (c *CacheService) RoleHierarchy() map[int64]map[int64]model.RoleHierarchy {
	res, _ := c.cache.Get(cacheKeyAll)
	return res.RoleHierarchy
}

func (c *CacheService) RolePermissions() map[int64]map[int64]model.RolePermission {
	res, _ := c.cache.Get(cacheKeyAll)
	return res.RolePermissions
}

func (c *CacheService) RolePermissionsHasRole(roleID int64) map[int64]model.RolePermission {
	res := c.RolePermissions()
	if res, ok := res[roleID]; ok {
		return res
	}

	return nil
}

func (c *CacheService) SubjectRoles(subjectID string) []model.Role {
	data, ok := c.cache.Get(cacheKeyAll)
	if !ok {
		return nil
	}

	subjectRoles, ok := data.SubjectRole[subjectID]
	if !ok {
		return nil
	}

	roles := make([]model.Role, 0, len(subjectRoles))
	for _, role := range subjectRoles {
		if r, ok := data.Roles[role.RoleID]; ok {
			roles = append(roles, r)
		}
	}

	return roles
}

func (c *CacheService) AllRolePermissions(roles []model.Role) map[int64]map[int64]model.Permission {
	data, ok := c.cache.Get(cacheKeyAll)
	if !ok {
		return nil
	}

	all := make(map[int64]map[int64]model.Permission, len(roles))
	for _, role := range roles {
		rolePermissions, ok := data.RolePermissions[role.ID]
		if !ok {
			continue
		}

		permissions := make(map[int64]model.Permission, len(rolePermissions))
		for _, perm := range rolePermissions {
			if p, ok := data.Permissions[perm.PermissionID]; ok {
				permissions[perm.PermissionID] = p
			}
		}

		all[role.ID] = permissions
	}

	return all
}
