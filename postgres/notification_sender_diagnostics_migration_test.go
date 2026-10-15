//nolint:testpackage // Pin immutable migration history at the additive schema boundary.
package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNotificationSenderDiagnosticsMigrationPreservesHistory(t *testing.T) {
	t.Parallel()
	require.Equal(t, 13, schemaVersion)
	require.Equal(t, 12, notificationLifecycleSchemaVersion)
	require.Equal(t, schemaVersion, notificationSenderDiagnosticsSchemaVersion)
	for version := 2; version <= schemaVersion; version++ {
		require.True(t, supportedSchemaVersion(version))
	}
	require.False(t, supportedSchemaVersion(1))
	require.False(t, supportedSchemaVersion(schemaVersion+1))
	for file, expected := range map[string]string{
		"migrations/00001_v0_2_baseline.sql":          "b1581da635f5f67d64583fe5256aac778ee70749f79b39ba330f37263f9a353a",
		"migrations/00002_notifications.sql":          "29f82c30c9bf7b661b1fc2633ae42ac6fa0cbb6c02ea84f1e6e068d0d5519a21",
		"migrations/00003_local_identity.sql":         "2bdec297c3440bfa10e6d422585cbf9995a84a08ef78d2c2f462977ca6925ba6",
		"migrations/00004_notification_expiry.sql":    "346090a6c0ecbc44d18b7c487086970d349a34f51565b3c83faa5852dc3950ce",
		"migrations/00005_subject_retirement.sql":     "476430b6c87d2a915218f4e74cb526896440bfc47f50ea2158e6a61453c43865",
		"migrations/00006_rate_event_cleanup.sql":     "73d3cbce006273a6dc3db1202bd046bb2de9a0e95cf5766ad67eba6d67ca4552",
		"migrations/00007_session_oidc.sql":           "8d3188f00aed7ecfe9a352e5c89e649033af04ab2c8b6a1575591310803302c5",
		"migrations/00008_local_mfa.sql":              "dd7ee1dcfd9043322ead81e17140422b0645c1c0de531df3225429b66dc4fa85",
		"migrations/00009_required_mfa.sql":           "8da8569aafa5f778b833d1fb90385fe03dfb74d9377965bcff8b1c263e4d57ea",
		"migrations/00010_scoped_email_change.sql":    "bc38855b8482e3069d2b4e11e0ce14ba544394d85897cc8729e69c851c1a1d08",
		"migrations/00011_notification_lifecycle.sql": "8153ba2ac8d1850f508530fd5a917af8f7193892d2284c05d28fe7db6c1ad89e",
	} {
		data, err := migrationFiles.ReadFile(file)
		require.NoError(t, err)
		sum := sha256.Sum256(data)
		require.Equal(t, expected, hex.EncodeToString(sum[:]), file)
	}
}
