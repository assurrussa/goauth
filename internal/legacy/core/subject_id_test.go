package core_test

import (
	"testing"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	authshared "github.com/assurrussa/goauth/internal/legacy/shared"
)

func TestSubjectAuthSubjectIDUsesTypedPublicID(t *testing.T) {
	subjectID := authshared.NewSubjectID()

	subject := authcore.Subject{ID: subjectID}

	require.Equal(t, subjectID, subject.AuthSubjectID())
	require.Equal(t, subjectID.String(), subject.CanonicalID())
}

func TestSubjectAuthSubjectIDUsesSubjectIDOnly(t *testing.T) {
	userID := sharedtypes.NewUserID()

	subject := authcore.Subject{
		Kind:     authcore.SubjectKindAdmin,
		PublicID: userID,
	}

	require.Equal(t, authshared.SubjectIDNil, subject.AuthSubjectID())
	require.Empty(t, subject.CanonicalID())
}

func TestProfileAuthSubjectIDUsesSubjectIDOnly(t *testing.T) {
	subjectID := authshared.NewSubjectID()
	userID := sharedtypes.NewUserID()

	profile := authcore.Profile{
		SubjectID: subjectID,
		PublicID:  userID,
	}

	require.Equal(t, subjectID, profile.AuthSubjectID())

	profile.SubjectID = authshared.SubjectIDNil
	require.Equal(t, authshared.SubjectIDNil, profile.AuthSubjectID())
}

func TestAuthSessionIsZeroIgnoresPublicID(t *testing.T) {
	session := authcore.AuthSession{}

	require.True(t, session.IsZero())
}
