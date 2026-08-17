package goauth_test

import (
	"database/sql/driver"
	"encoding"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestSubjectIDPublicContract(t *testing.T) {
	t.Parallel()

	created := goauth.NewSubjectID()
	require.NoError(t, created.Validate())
	require.False(t, created.IsZero())

	parsed, err := goauth.ParseSubjectID("  " + created.String() + "  ")
	require.NoError(t, err)
	require.Equal(t, created, parsed)

	value, err := created.Value()
	require.NoError(t, err)
	require.Equal(t, driver.Value(created.String()), value)

	var scanned goauth.SubjectID
	require.NoError(t, scanned.Scan(created.String()))
	require.Equal(t, created, scanned)

	encoded, err := created.MarshalText()
	require.NoError(t, err)

	var decoded goauth.SubjectID
	require.NoError(t, decoded.UnmarshalText(encoded))
	require.Equal(t, created, decoded)

	var _ encoding.TextMarshaler = created
	var _ encoding.TextUnmarshaler = &decoded
}

func TestSubjectIDRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	_, err := goauth.ParseSubjectID("not-a-uuid")
	require.ErrorIs(t, err, goauth.ErrInvalidSubjectID)
	require.ErrorIs(t, goauth.NilSubjectID.Validate(), goauth.ErrInvalidSubjectID)
	require.Panics(t, func() { goauth.MustParseSubjectID("not-a-uuid") })
}
