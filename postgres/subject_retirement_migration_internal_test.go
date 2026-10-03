package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRetirementMigrationPreservesPublishedMigrationBytes(t *testing.T) {
	t.Parallel()
	for filename, want := range map[string]string{
		"00001_v0_2_baseline.sql":       "b1581da635f5f67d64583fe5256aac778ee70749f79b39ba330f37263f9a353a",
		"00002_notifications.sql":       "29f82c30c9bf7b661b1fc2633ae42ac6fa0cbb6c02ea84f1e6e068d0d5519a21",
		"00003_local_identity.sql":      "2bdec297c3440bfa10e6d422585cbf9995a84a08ef78d2c2f462977ca6925ba6",
		"00004_notification_expiry.sql": "346090a6c0ecbc44d18b7c487086970d349a34f51565b3c83faa5852dc3950ce",
	} {
		t.Run(filename, func(t *testing.T) {
			t.Parallel()
			data, err := migrationFiles.ReadFile("migrations/" + filename)
			require.NoError(t, err)
			checksum := sha256.Sum256(data)
			require.Equal(t, want, hex.EncodeToString(checksum[:]))
		})
	}
}

func TestRetirementMigrationDoesNotRenumberEarlierVersions(t *testing.T) {
	t.Parallel()
	require.Equal(t, 3, notificationSchemaVersion)
	require.Equal(t, 4, localIdentitySchemaVersion)
	require.Equal(t, 5, notificationExpirySchemaVersion)
	require.Equal(t, 6, subjectRetirementSchemaVersion)
	require.GreaterOrEqual(t, schemaVersion, subjectRetirementSchemaVersion)
}
