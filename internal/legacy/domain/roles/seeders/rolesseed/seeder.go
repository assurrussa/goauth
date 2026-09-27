package rolesseed

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/assurrussa/goshared/pkg/pointer"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/repository"
	rolesrepo "github.com/assurrussa/goauth/internal/legacy/domain/roles/repository/postgres"
	rolesservice "github.com/assurrussa/goauth/internal/legacy/domain/roles/service/roles"
	"github.com/assurrussa/goauth/internal/legacy/domain/roles/shared"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

const (
	name                 = "rolesseed"
	superAdminRoleSlug   = "super_admin"
	contentAdminRoleSlug = "content_admin"
)

type Seed struct {
	pgsql                 outbox.StoragePgsqlClient
	repoRoles             *rolesrepo.Repo
	svc                   *rolesservice.Service
	permissionDefinitions []shared.PermissionDefinition
	rolePresets           []RolePreset
}

type Option func(*Seed)

// RolePreset describes a canonical role managed by the roles seeder.
// Permissions must be present in the combined built-in and host permission catalog.
type RolePreset struct {
	Slug        string
	Name        string
	Description string
	IsSystem    bool
	Permissions []shared.PermissionKey
}

// WithPermissionDefinitions appends host-owned permission definitions to the seed catalog.
func WithPermissionDefinitions(definitions ...shared.PermissionDefinition) Option {
	return func(seed *Seed) {
		seed.permissionDefinitions = shared.MergePermissionDefinitions(seed.permissionDefinitions, definitions)
	}
}

// WithRolePresets appends host-owned role presets to the built-in role seed.
// Input slices are copied so callers cannot mutate seeder policy after construction.
func WithRolePresets(presets ...RolePreset) Option {
	return func(seed *Seed) {
		seed.rolePresets = append(seed.rolePresets, cloneRolePresets(presets)...)
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

	seedRoles, err := buildSeedRoles(catalog, s.rolePresets)
	if err != nil {
		return fmt.Errorf("build roles seed %s: %w", s.Name(), err)
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

func buildSeedRoles(catalog shared.PermissionCatalog, presets []RolePreset) ([]seedRole, error) {
	seedRoles := []seedRole{
		{
			Slug:        superAdminRoleSlug,
			Name:        "Супер-администратор",
			Description: "Полный доступ ко всем действиям админ-панели",
			IsSystem:    true,
			Permissions: catalog.GetPermissions(),
		},
		{
			Slug:        contentAdminRoleSlug,
			Name:        "Контент-администратор",
			Description: "Просмотр ролей и разрешений; доступ к CMS назначается отдельной CMS-ролью",
			IsSystem:    true,
			Permissions: []shared.PermissionKey{
				shared.NewPermissionKey(shared.PermissionDomainRoles, shared.PermissionActionRead),
				shared.NewPermissionKey(shared.PermissionDomainPermissions, shared.PermissionActionRead),
			},
		},
	}

	knownPermissions := make(map[shared.PermissionKey]struct{}, len(catalog.Data))
	for _, definition := range catalog.Data {
		knownPermissions[definition.Key] = struct{}{}
	}
	seenSlugs := map[string]struct{}{
		superAdminRoleSlug:   {},
		contentAdminRoleSlug: {},
	}
	for _, preset := range presets {
		slug := strings.TrimSpace(preset.Slug)
		if slug == "" {
			return nil, errors.New("role preset slug is required")
		}
		if _, exists := seenSlugs[slug]; exists {
			return nil, fmt.Errorf("duplicate or reserved role preset slug %q", slug)
		}
		name := strings.TrimSpace(preset.Name)
		if name == "" {
			return nil, fmt.Errorf("role preset %q name is required", slug)
		}
		seenSlugs[slug] = struct{}{}
		for _, permission := range preset.Permissions {
			if _, exists := knownPermissions[permission]; !exists {
				return nil, fmt.Errorf("role preset %q references permission %q outside the seed catalog", slug, permission)
			}
		}
		seedRoles = append(seedRoles, seedRole{
			Slug:        slug,
			Name:        name,
			Description: preset.Description,
			IsSystem:    preset.IsSystem,
			Permissions: append([]shared.PermissionKey(nil), preset.Permissions...),
		})
	}
	return seedRoles, nil
}

type seedRole struct {
	Slug        string
	Name        string
	Description string
	IsSystem    bool
	Permissions []shared.PermissionKey
}

func cloneRolePresets(presets []RolePreset) []RolePreset {
	cloned := make([]RolePreset, len(presets))
	for i, preset := range presets {
		cloned[i] = preset
		cloned[i].Permissions = append([]shared.PermissionKey(nil), preset.Permissions...)
	}
	return cloned
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
