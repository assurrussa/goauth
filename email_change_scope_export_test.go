package goauth

import "context"

// Test-only bridges keep internal security invariants covered without adding
// symbols to the published package.
var (
	EmailChangedNotificationDataForTest = emailChangedNotificationData
	RuntimeEmailChangeTargetsForTest    = runtimeEmailChangeTargets
	EmailChangeSecretForTest            = emailChangeSecret
	ValidEmailChangeCodeForTest         = validEmailChangeCode
	ValidEmailChangeSnapshotForTest     = validEmailChangeSnapshot
)

func EmailChangeTargetForTest(ctx context.Context, store RuntimeStore, targets map[EmailChangeScope]EmailChangeTarget) (
	EmailChangeScope, EmailChangeTarget, error,
) {
	runtime := &Runtime{store: store, emailChangeTargets: targets}
	return runtime.emailChangeTarget(ctx)
}
