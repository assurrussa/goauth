//go:build integration

package rolesseed_test

import (
	"context"
	"testing"

	tests "github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/assurrussa/goauth/domain/roles/model"
	"github.com/assurrussa/goauth/domain/roles/seeders/rolesseed"
	"github.com/assurrussa/goauth/domain/roles/shared"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	outboxtest "github.com/assurrussa/goauth/infrastructure/outbox/testsupport"
)

const cmsEditorRoleSlug = "cms_editor"

type TestRepoSuite struct {
	suite.Suite

	db       outbox.StoragePgsqlClient
	dbHelper *outboxtest.DBHelper
	cleanUp  func(context.Context)

	seed *rolesseed.Seed
}

func NewTestSeedSuite(t *testing.T, opts ...outboxtest.OptionDatabase) (context.Context, context.CancelFunc, *TestRepoSuite) {
	return tests.NewSuite[*TestRepoSuite](t, func(t *testing.T, ctx context.Context) *TestRepoSuite {
		opts = append([]outboxtest.OptionDatabase{
			outboxtest.WithDatabasePathFilesMigration("migrations/sql"),
		}, opts...)
		db, dbHelper, cleanUp := outboxtest.PrepareDB(ctx, t, "TestRolesSeedSuite", opts...)
		seed := rolesseed.NewSeed(db)

		return &TestRepoSuite{
			db:       db,
			dbHelper: dbHelper,
			cleanUp:  cleanUp,
			seed:     seed,
		}
	})
}

func TestSeedIntegration_Handle(t *testing.T) {
	ctx, _, ts := NewTestSeedSuite(t)
	defer ts.cleanUp(ctx)

	require.Equal(t, "rolesseed", ts.seed.Name())

	sqlBuilder := outbox.BuilderDollar().Select("*").From("roles")

	var data []model.Role
	err := ts.db.DB().ScanAllx(ctx, "seed", &data, sqlBuilder)
	require.NoError(t, err)
	assert.Len(t, data, 0)

	err = ts.seed.Handle(ctx)
	require.NoError(t, err)

	err = ts.db.DB().ScanAllx(ctx, "seed", &data, sqlBuilder)
	require.NoError(t, err)
	assert.Len(t, data, 2)
}

func TestSeedIntegration_HandleWithRolePresetIsIdempotent(t *testing.T) {
	ctx, _, ts := NewTestSeedSuite(t)
	defer ts.cleanUp(ctx)

	permission := shared.NewPermissionKey("cms.entry", "read")
	ts.seed = rolesseed.NewSeed(
		ts.db,
		rolesseed.WithPermissionDefinitions(
			shared.PermissionDefinition{Key: permission, Description: "Read CMS entries"},
		),
		rolesseed.WithRolePresets(rolesseed.RolePreset{
			Slug: cmsEditorRoleSlug, Name: "CMS editor", IsSystem: true,
			Permissions: []shared.PermissionKey{permission},
		}),
	)

	require.NoError(t, ts.seed.Handle(ctx))
	require.NoError(t, ts.seed.Handle(ctx))

	var roles []model.Role
	err := ts.db.DB().ScanAllx(
		ctx,
		"seed role presets",
		&roles,
		outbox.BuilderDollar().Select("*").From("roles"),
	)
	require.NoError(t, err)
	require.Len(t, roles, 3)
	assert.Condition(t, func() bool {
		for _, role := range roles {
			if role.Slug == cmsEditorRoleSlug && role.Name == "CMS editor" && role.IsSystem {
				return true
			}
		}
		return false
	})
}
