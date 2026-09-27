package authinvalidator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	authinvalidator "github.com/assurrussa/goauth/internal/legacy/service/authinvalidator"
)

func TestServiceInvalidateAll(t *testing.T) {
	t.Parallel()
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174030")

	refresh := &storeFake{}
	sessions := &storeFake{}
	svc := authinvalidator.Must(authinvalidator.Options{
		RefreshTokens: refresh,
		Sessions:      sessions,
	})

	err := svc.InvalidateAll(context.Background(), subjectID)
	require.NoError(t, err)
	require.Equal(t, []authcore.SubjectID{subjectID}, refresh.deleteAllSubjects)
	require.Equal(t, []authcore.SubjectID{subjectID}, sessions.deleteAllSubjects)
}

func TestServiceInvalidateAllExcept_RefreshOnly(t *testing.T) {
	t.Parallel()
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174031")

	refresh := &storeFake{}
	svc := authinvalidator.Must(authinvalidator.Options{
		RefreshTokens: refresh,
	})

	err := svc.InvalidateAllExcept(context.Background(), subjectID, authinvalidator.KeepCurrent{
		RefreshToken: "refresh-keep", //nolint:goconst // autofix
	})
	require.NoError(t, err)
	require.Len(t, refresh.deleteAllExceptCalls, 1)
	require.Equal(t, deleteAllExceptCall{subjectID: subjectID, keepToken: "refresh-keep"}, refresh.deleteAllExceptCalls[0])
	require.Empty(t, refresh.deleteAllSubjects)
}

func TestServiceInvalidateAllExcept_SessionOnly(t *testing.T) {
	t.Parallel()
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174032")

	sessions := &storeFake{}
	svc := authinvalidator.Must(authinvalidator.Options{
		Sessions: sessions,
	})

	err := svc.InvalidateAllExcept(context.Background(), subjectID, authinvalidator.KeepCurrent{
		SessionToken: "session-keep", //nolint:goconst // autofix
	})
	require.NoError(t, err)
	require.Len(t, sessions.deleteAllExceptCalls, 1)
	require.Equal(t, deleteAllExceptCall{subjectID: subjectID, keepToken: "session-keep"}, sessions.deleteAllExceptCalls[0])
	require.Empty(t, sessions.deleteAllSubjects)
}

func TestServiceInvalidateAllExcept_KeepBoth(t *testing.T) {
	t.Parallel()
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174033")

	refresh := &storeFake{}
	sessions := &storeFake{}
	svc := authinvalidator.Must(authinvalidator.Options{
		RefreshTokens: refresh,
		Sessions:      sessions,
	})

	err := svc.InvalidateAllExcept(context.Background(), subjectID, authinvalidator.KeepCurrent{
		RefreshToken: "refresh-keep",
		SessionToken: "session-keep",
	})
	require.NoError(t, err)
	require.Equal(t, []deleteAllExceptCall{{subjectID: subjectID, keepToken: "refresh-keep"}}, refresh.deleteAllExceptCalls)
	require.Equal(t, []deleteAllExceptCall{{subjectID: subjectID, keepToken: "session-keep"}}, sessions.deleteAllExceptCalls)
}

func TestServiceInvalidateAllExcept_NoStores(t *testing.T) {
	t.Parallel()
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174034")

	svc := authinvalidator.Must(authinvalidator.Options{})

	err := svc.InvalidateAllExcept(context.Background(), subjectID, authinvalidator.KeepCurrent{
		RefreshToken: "refresh-keep",
		SessionToken: "session-keep",
	})
	require.NoError(t, err)
}

func TestServiceInvalidateAll_ReturnsStoreError(t *testing.T) {
	t.Parallel()
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174035")

	refresh := &storeFake{deleteAllErr: errors.New("boom")}
	svc := authinvalidator.Must(authinvalidator.Options{
		RefreshTokens: refresh,
	})

	err := svc.InvalidateAll(context.Background(), subjectID)
	require.Error(t, err)
	require.ErrorContains(t, err, "invalidate refresh tokens")
	require.ErrorContains(t, err, "boom")
}

type deleteAllExceptCall struct {
	subjectID authcore.SubjectID
	keepToken string
}

type storeFake struct {
	deleteAllSubjects    []authcore.SubjectID
	deleteAllExceptCalls []deleteAllExceptCall
	deleteAllErr         error
	deleteAllExceptErr   error
}

func (f *storeFake) DeleteAll(_ context.Context, subjectID authcore.SubjectID) (int64, error) {
	f.deleteAllSubjects = append(f.deleteAllSubjects, subjectID)
	if f.deleteAllErr != nil {
		return 0, f.deleteAllErr
	}
	return 1, nil
}

func (f *storeFake) DeleteAllExcept(_ context.Context, subjectID authcore.SubjectID, keepToken string) (int64, error) {
	f.deleteAllExceptCalls = append(f.deleteAllExceptCalls, deleteAllExceptCall{subjectID: subjectID, keepToken: keepToken})
	if f.deleteAllExceptErr != nil {
		return 0, f.deleteAllExceptErr
	}
	return 1, nil
}
