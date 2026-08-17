package shared_test

import (
	"database/sql/driver"
	"encoding"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/assurrussa/goauth/internal/legacy/shared"
)

var _ interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler
	gomock.Matcher
} = (*shared.SubjectID)(nil)

func TestParse(t *testing.T) {
	_, err := shared.Parse[shared.SubjectID]("abra-cadabra")
	require.Error(t, err)

	RequestID, err := shared.Parse[shared.SubjectID]("f0317e88-bbfe-11ed-8728-461e464ebed8")
	require.NoError(t, err)
	assert.Equal(t, "f0317e88-bbfe-11ed-8728-461e464ebed8", RequestID.String())
}

func TestMustParse(t *testing.T) {
	assert.Panics(t, func() {
		shared.MustParse[shared.SubjectID]("abra-cadabra")
	})

	assert.NotPanics(t, func() {
		RequestID := shared.MustParse[shared.SubjectID]("f0317e88-bbfe-11ed-8728-461e464ebed8")
		assert.Equal(t, "f0317e88-bbfe-11ed-8728-461e464ebed8", RequestID.String())
	})
}

func TestRequestIDNil(t *testing.T) {
	t.Log(shared.SubjectIDNil)
	assert.Equal(t, shared.SubjectIDNil.String(), uuid.Nil.String())
}

func TestRequestID_String(t *testing.T) {
	id := shared.NewSubjectID()
	require.NotEmpty(t, id.String())
	assert.Equal(t, uuid.MustParse(id.String()).String(), id.String())
}

func TestRequestID_Scan(t *testing.T) {
	const src = "5c9de646-529c-11ed-81ba-461e464ebed9"

	t.Run("from string and bytes", func(t *testing.T) {
		var id1, id2 shared.SubjectID
		{
			err := id1.Scan(src)
			require.NoError(t, err)
		}
		{
			err := id2.Scan([]byte(src))
			require.NoError(t, err)
		}
		assert.Equal(t, id1.String(), id2.String())
		assert.Equal(t, getValueAsString(t, id1), getValueAsString(t, id2))
	})

	t.Run("from NULL", func(t *testing.T) {
		for _, src := range []any{nil, []byte(nil), []byte{}, ""} {
			t.Run("", func(t *testing.T) {
				var id shared.SubjectID
				err := id.Scan(src)
				require.NoError(t, err)
				assert.Equal(t, shared.SubjectIDNil.String(), id.String())
				assert.Equal(t, shared.SubjectIDNil.String(), getValueAsString(t, id))
			})
		}
	})
}

func TestRequestID_MarshalText(t *testing.T) {
	RequestID := shared.MustParse[shared.SubjectID]("f0317e88-bbfe-11ed-8728-461e464ebed8")
	v, err := RequestID.MarshalText()
	require.NoError(t, err)
	assert.Equal(t, "f0317e88-bbfe-11ed-8728-461e464ebed8", string(v))

	var RequestID2 shared.SubjectID
	err = RequestID2.UnmarshalText(v)
	require.NoError(t, err)
	assert.Equal(t, RequestID.String(), RequestID2.String())
}

func TestSubjectIDMarshalJSON(t *testing.T) {
	const raw = "123e4567-e89b-12d3-a456-426614174000"
	subjectID := shared.MustParse[shared.SubjectID](raw)

	jsonBytes, err := json.Marshal(subjectID)
	require.NoError(t, err)
	require.JSONEq(t, `"`+raw+`"`, string(jsonBytes))

	var fromJSON shared.SubjectID
	require.NoError(t, json.Unmarshal(jsonBytes, &fromJSON))
	require.Equal(t, subjectID, fromJSON)
}

func TestRequestID_IsZero(t *testing.T) {
	id := shared.NewSubjectID()
	assert.False(t, id.IsZero())
	assert.True(t, shared.SubjectIDNil.IsZero())
	assert.Equal(t, uuid.Nil.String(), shared.SubjectIDNil.String())
}

func TestRequestID_Matches(t *testing.T) {
	id := shared.NewSubjectID()
	id2 := shared.MustParse[shared.SubjectID](id.String())
	assert.Equal(t, id, id2)
	assert.True(t, id.Matches(id2))
	assert.NotEqual(t, id, id2.String())
	assert.NotEqual(t, id, shared.NewSubjectID())
}

func TestRequestID_Validate(t *testing.T) {
	require.NoError(t, shared.NewSubjectID().Validate())
	require.Error(t, shared.SubjectID{}.Validate())
	require.Error(t, shared.SubjectIDNil.Validate())
}

func TestSubjectIDRejectsPrefixedValues(t *testing.T) {
	_, err := shared.Parse[shared.SubjectID]("user:123e4567-e89b-12d3-a456-426614174000")
	require.Error(t, err)

	var fromText shared.SubjectID
	require.Error(t, fromText.UnmarshalText([]byte("admin:123e4567-e89b-12d3-a456-426614174000")))

	var fromScan shared.SubjectID
	require.Error(t, fromScan.Scan("admin:123e4567-e89b-12d3-a456-426614174000"))
}

func getValueAsString(t *testing.T, valuer driver.Valuer) string {
	t.Helper()

	v, err := valuer.Value()
	require.NoError(t, err)
	vv, ok := v.(string)
	require.True(t, ok)
	return vv
}
