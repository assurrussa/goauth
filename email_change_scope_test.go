package goauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

type scopedEmailStoreProbe struct{ goauth.RuntimeStore }

func TestScopedEmailChangedNoticeNamesOnlyTrustedScope(t *testing.T) {
	t.Parallel()
	require.Nil(t, goauth.EmailChangedNotificationDataForTest(""))
	require.Equal(t, map[string]string{"email_change_scope": "test-host-v1"},
		goauth.EmailChangedNotificationDataForTest("test-host-v1"))
}

func (scopedEmailStoreProbe) IssueScopedEmailChange(
	context.Context, goauth.EmailChangeRecord, goauth.EmailChallengeLimits,
) (goauth.EmailChangeIssueResult, error) {
	return goauth.EmailChangeIssueResult{}, nil
}

func (scopedEmailStoreProbe) GetPendingScopedEmailChange(
	context.Context, goauth.SubjectID, goauth.EmailChangeScope, time.Time,
) (goauth.PendingEmailChange, error) {
	return goauth.PendingEmailChange{}, nil
}

func (scopedEmailStoreProbe) VerifyScopedEmailChange(
	context.Context, goauth.EmailChangeVerifyRequest,
) (goauth.EmailChangeVerifyResult, error) {
	return goauth.EmailChangeVerifyResult{}, nil
}

type scopedEmailTargetProbe struct{}

func (scopedEmailTargetProbe) SnapshotEmailChangeTarget(
	context.Context, goauth.SubjectID,
) (goauth.EmailChangeTargetSnapshot, error) {
	return goauth.EmailChangeTargetSnapshot{}, nil
}

func (scopedEmailTargetProbe) ApplyVerifiedEmailChange(
	context.Context, goauth.SubjectID, goauth.EmailChangeTargetSnapshot, string, time.Time,
) error {
	return nil
}

func TestScopedEmailConfigurationFailsClosedAndCopiesMap(t *testing.T) {
	target := scopedEmailTargetProbe{}
	scope := goauth.EmailChangeScope("host-alias-v1")
	targets := map[goauth.EmailChangeScope]goauth.EmailChangeTarget{scope: target}
	_, err := goauth.RuntimeEmailChangeTargetsForTest(nil, targets)
	require.ErrorIs(t, err, goauth.ErrEmailChangeScopeUnavailable)
	copied, err := goauth.RuntimeEmailChangeTargetsForTest(scopedEmailStoreProbe{}, targets)
	require.NoError(t, err)
	delete(targets, scope)
	require.NotNil(t, copied[scope])
	for _, invalid := range []goauth.EmailChangeScope{"", "UPPER", "bad space", "x/y"} {
		_, err := goauth.RuntimeEmailChangeTargetsForTest(scopedEmailStoreProbe{},
			map[goauth.EmailChangeScope]goauth.EmailChangeTarget{invalid: target})
		require.ErrorIs(t, err, goauth.ErrEmailChangeScopeUnavailable)
	}
	_, _, err = goauth.EmailChangeTargetForTest(goauth.WithEmailChangeScope(context.Background(), "unknown"),
		scopedEmailStoreProbe{}, copied)
	require.ErrorIs(t, err, goauth.ErrEmailChangeScopeUnavailable)
	gotScope, gotTarget, err := goauth.EmailChangeTargetForTest(context.Background(), scopedEmailStoreProbe{}, copied)
	require.NoError(t, err)
	require.Empty(t, gotScope)
	require.Nil(t, gotTarget)
}

func TestScopedEmailSecretBindsEveryTargetAndRequestField(t *testing.T) {
	subject, err := goauth.ParseSubjectID("11111111-1111-4111-8111-111111111111")
	require.NoError(t, err)
	record := goauth.EmailChangeRecord{
		ID: "request-one", SubjectID: subject, Scope: "host-alias-v1",
		ExpectedSecurityVersion: 7, TargetSnapshot: goauth.EmailChangeTargetSnapshot{Version: 3, NormalizedEmail: "old@example.test"},
		NewNormalizedValue: "new@example.test",
	}
	purpose, value, err := goauth.EmailChangeSecretForTest(record, "123456")
	require.NoError(t, err)
	require.Equal(t, "email-change/host-v1", purpose)
	const encoded = `["host-alias-v1","11111111-1111-4111-8111-111111111111","request-one",` +
		`"7","3","old@example.test","new@example.test","123456"]`
	require.Equal(t, encoded, value)
	mutations := []func(*goauth.EmailChangeRecord){
		func(r *goauth.EmailChangeRecord) { r.ID = "request-two" },
		func(r *goauth.EmailChangeRecord) { r.SubjectID = goauth.SubjectID{} },
		func(r *goauth.EmailChangeRecord) { r.Scope = "another-host" },
		func(r *goauth.EmailChangeRecord) { r.ExpectedSecurityVersion++ },
		func(r *goauth.EmailChangeRecord) { r.TargetSnapshot.Version++ },
		func(r *goauth.EmailChangeRecord) { r.TargetSnapshot.NormalizedEmail = "changed@example.test" },
		func(r *goauth.EmailChangeRecord) { r.NewNormalizedValue = "other@example.test" },
	}
	for _, mutate := range mutations {
		changed := record
		mutate(&changed)
		_, other, err := goauth.EmailChangeSecretForTest(changed, "123456")
		require.NoError(t, err)
		require.NotEqual(t, value, other)
	}
	_, other, err := goauth.EmailChangeSecretForTest(record, "654321")
	require.NoError(t, err)
	require.NotEqual(t, value, other)
	purpose, value, err = goauth.EmailChangeSecretForTest(goauth.EmailChangeRecord{}, "123456")
	require.NoError(t, err)
	require.Equal(t, "email-change", purpose)
	require.Equal(t, "123456", value)
}

func TestScopedEmailCodeAndSnapshotValidation(t *testing.T) {
	for _, code := range []string{"", "12345", "1234567", "１２３４５６", "12 456", testNonNumericCode} {
		require.False(t, goauth.ValidEmailChangeCodeForTest(code))
	}
	require.True(t, goauth.ValidEmailChangeCodeForTest("123456"))
	require.True(t, goauth.ValidEmailChangeSnapshotForTest(goauth.EmailChangeTargetSnapshot{Version: 1}))
	require.False(t, goauth.ValidEmailChangeSnapshotForTest(goauth.EmailChangeTargetSnapshot{}))
	require.False(t, goauth.ValidEmailChangeSnapshotForTest(
		goauth.EmailChangeTargetSnapshot{Version: 1, NormalizedEmail: "UPPER@example.test"}))
	require.True(t, goauth.ValidEmailChangeSnapshotForTest(
		goauth.EmailChangeTargetSnapshot{Version: 1, NormalizedEmail: "user@example.test"}))
}
