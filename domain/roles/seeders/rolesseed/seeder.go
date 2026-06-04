package rolesseed

import (
	"context"
	"fmt"

	"github.com/assurrussa/goshared/pkg/pointer"

	"github.com/assurrussa/goauth/domain/roles/repository"
	rolesrepo "github.com/assurrussa/goauth/domain/roles/repository/postgres"
	rolesservice "github.com/assurrussa/goauth/domain/roles/service/roles"
	"github.com/assurrussa/goauth/domain/roles/shared"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

const name = "rolesseed"

type Seed struct {
	pgsql                 outbox.StoragePgsqlClient
	repoRoles             *rolesrepo.Repo
	svc                   *rolesservice.Service
	permissionDefinitions []shared.PermissionDefinition
}

type Option func(*Seed)

// WithPermissionDefinitions appends host-owned permission definitions to the seed catalog.
func WithPermissionDefinitions(definitions ...shared.PermissionDefinition) Option {
	return func(seed *Seed) {
		seed.permissionDefinitions = shared.MergePermissionDefinitions(seed.permissionDefinitions, definitions)
	}
}

func NewSeed(pgsql outbox.StoragePgsqlClient, opts ...Option) *Seed {
	repoRoles := rolesrepo.Must(rolesrepo.Options{
		Pgsql:     pgsql,
		TxManager: outbox.PgsqlTrxNew(pgsql.DB()),
	})

	seed := &Seed{
		pgsql:                 pgsql,
		repoRoles:             repoRoles,
		permissionDefinitions: shared.ClonePermissionDefinitions(shared.DefaultPermissionDefinitions().Data),
		svc: rolesservice.Must(rolesservice.Dependencies{
			Roles:       repoRoles,
			Permissions: repoRoles,
			Assignments: repoRoles,
			Hierarchy:   repoRoles,
		}),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(seed)
		}
	}

	return seed
}

func (s *Seed) Name() string {
	return name
}

func (s *Seed) Handle(ctx context.Context) error {
	catalog := shared.NewPermissionCatalog(s.permissionDefinitions)
	permissionsInput := make([]rolesservice.CreatePermissionInput, 0, len(catalog.Data))
	for _, def := range catalog.Data {
		permissionsInput = append(permissionsInput, rolesservice.CreatePermissionInput{
			Key:         def.Key,
			Description: def.Description,
		})
	}

	seedRoles := []seedRole{
		{
			Slug:        "super_admin",
			Name:        "Супер-администратор",
			Description: "Полный доступ ко всем действиям админ-панели",
			IsSystem:    true,
			Permissions: catalog.GetPermissions(),
		},
		{
			Slug:        "content_admin",
			Name:        "Контент-администратор",
			Description: "Управление контентом и просмотр ролей",
			IsSystem:    true,
			Permissions: []shared.PermissionKey{
				shared.NewPermissionKey(shared.PermissionDomainRoles, shared.PermissionActionRead),
				shared.NewPermissionKey(shared.PermissionDomainPermissions, shared.PermissionActionRead),
			},
		},
	}

	if err := s.ensurePermissionsSeed(ctx, permissionsInput); err != nil {
		return fmt.Errorf("ensure permissions seed %s: %w", s.Name(), err)
	}

	for _, role := range seedRoles {
		if err := s.upsertRole(ctx, role); err != nil {
			return fmt.Errorf("seeder %s: role [%s]: %w", s.Name(), role.Slug, err)
		}
	}

	return nil
}

type seedRole struct {
	Slug        string
	Name        string
	Description string
	IsSystem    bool
	Permissions []shared.PermissionKey
}

func (s *Seed) ensurePermissionsSeed(ctx context.Context, inputs []rolesservice.CreatePermissionInput) error {
	if err := s.svc.EnsurePermissions(ctx, inputs); err != nil {
		return fmt.Errorf("ensuring permissions: %w", err)
	}

	// Ensure descriptions are set for existing permissions (ignore errors).
	_, _ = s.svc.CreatePermissions(ctx, inputs)

	return nil
}

func (s *Seed) upsertRole(ctx context.Context, role seedRole) error {
	existing, err := s.svc.ListRoles(ctx, repository.RoleFilter{
		Slugs:      []string{role.Slug},
		IncludeSys: true,
	})
	if err != nil {
		return err
	}

	if len(existing) > 0 {
		_, err = s.svc.UpdateRole(ctx, rolesservice.UpdateRoleInput{
			ID:          existing[0].ID,
			Slug:        role.Slug,
			Name:        role.Name,
			Description: &role.Description,
			IsSystem:    ptr(role.IsSystem),
			Permissions: pointer.To(role.Permissions),
		})
		return err
	}

	_, err = s.svc.CreateRole(ctx, rolesservice.CreateRoleInput{
		Slug:        role.Slug,
		Name:        role.Name,
		Description: &role.Description,
		IsSystem:    role.IsSystem,
		Permissions: role.Permissions,
	})
	return err
}

func ptr[T any](value T) *T {
	v := value
	return &v
}
