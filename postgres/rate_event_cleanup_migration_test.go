//nolint:testpackage // Pin all previous migration constants and bytes at this additive boundary.
package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRateEventCleanupMigrationPreservesRetirementBaseline(t *testing.T) {
	t.Parallel()
	require.Equal(t, 3, notificationSchemaVersion)
	require.Equal(t, 4, localIdentitySchemaVersion)
	require.Equal(t, 5, notificationExpirySchemaVersion)
	require.Equal(t, 6, subjectRetirementSchemaVersion)
	require.Equal(t, 7, rateEventCleanupSchemaVersion)
	require.Equal(t, 7, schemaVersion)
	data, err := migrationFiles.ReadFile("migrations/00005_subject_retirement.sql")
	require.NoError(t, err)
	checksum := sha256.Sum256(data)
	require.Equal(t, "476430b6c87d2a915218f4e74cb526896440bfc47f50ea2158e6a61453c43865", hex.EncodeToString(checksum[:]))
}
