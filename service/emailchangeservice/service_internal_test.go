package emailchangeservice

import (
	"testing"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/core"
	authshared "github.com/assurrussa/goauth/shared"
)

func TestAuthSubjectIDRequiresCanonicalIDForProfileUserID(t *testing.T) {
	t.Parallel()

	got := authSubjectID(Subject[sharedtypes.UserID]{
		ID: sharedtypes.NewUserID(),
	})

	require.Equal(t, authshared.SubjectIDNil, got)
}

func TestAuthSubjectIDAcceptsTypedSubjectID(t *testing.T) {
	t.Parallel()

	subjectID := authshared.NewSubjectID()
	got := authSubjectID(Subject[authcore.SubjectID]{
		ID: subjectID,
	})

	require.Equal(t, subjectID, got)
}
