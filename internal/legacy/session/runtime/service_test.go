//nolint:testpackage // internal test
package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

type testPayload struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

type sessionStoreStub struct {
	session     authcore.AuthSession
	payload     []byte
	saveSession authcore.AuthSession
	savePayload []byte
	deleted     []string
	getErr      error
	saveErr     error
	deleteErr   error
}

func (s *sessionStoreStub) Save(_ context.Context, session authcore.AuthSession, payload []byte) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saveSession = session
	s.savePayload = append([]byte(nil), payload...)
	return nil
}

func (s *sessionStoreStub) Get(_ context.Context, _ string) (authcore.AuthSession, []byte, error) {
	if s.getErr != nil {
		return authcore.AuthSession{}, nil, s.getErr
	}
	return s.session, append([]byte(nil), s.payload...), nil
}

func (s *sessionStoreStub) Delete(_ context.Context, token string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, token)
	return nil
}

func TestServiceSaveAndLoad(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 18, 15, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174001")
	store := &sessionStoreStub{}
	svc := Must[testPayload](Options[testPayload]{
		Store: store,
		Now:   func() time.Time { return now },
	})

	session := authcore.AuthSession{
		SubjectID:       subjectID,
		Kind:            authcore.SubjectKindAdmin,
		Token:           "sess-1",
		PasswordVersion: 5,
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Hour),
	}
	payload := testPayload{ID: 1, Email: "admin@example.com"}

	require.NoError(t, svc.Save(context.Background(), session, payload))
	require.JSONEq(t, `{"id":1,"email":"admin@example.com"}`, string(store.savePayload))

	store.session = session
	store.payload = store.savePayload

	record, err := svc.Load(context.Background(), "sess-1")
	require.NoError(t, err)
	assert.Equal(t, session.Token, record.Session.Token)
	assert.Equal(t, payload, record.Payload)
}

func TestServiceLoadExpiredSessionDeletesCanonicalRecord(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 18, 15, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174002")
	store := &sessionStoreStub{
		session: authcore.AuthSession{
			SubjectID: subjectID,
			Kind:      authcore.SubjectKindAdmin,
			Token:     "sess-expired",
			ExpiresAt: now.Add(-time.Minute),
		},
		payload: []byte(`{"id":1}`),
	}
	svc := Must[testPayload](Options[testPayload]{
		Store: store,
		Now:   func() time.Time { return now },
	})

	_, err := svc.Load(context.Background(), "sess-expired")
	require.ErrorIs(t, err, ErrSessionExpired)
	require.Equal(t, []string{"sess-expired"}, store.deleted)
}

func TestServiceLoadRevokedSessionDeletesCanonicalRecord(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 18, 15, 0, 0, 0, time.UTC)
	revokedAt := now.Add(-time.Minute)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174003")
	store := &sessionStoreStub{
		session: authcore.AuthSession{
			SubjectID: subjectID,
			Kind:      authcore.SubjectKindAdmin,
			Token:     "sess-revoked",
			ExpiresAt: now.Add(time.Hour),
			RevokedAt: &revokedAt,
		},
		payload: []byte(`{"id":1}`),
	}
	svc := Must[testPayload](Options[testPayload]{
		Store: store,
		Now:   func() time.Time { return now },
	})

	_, err := svc.Load(context.Background(), "sess-revoked")
	require.ErrorIs(t, err, ErrSessionRevoked)
	require.Equal(t, []string{"sess-revoked"}, store.deleted)
}

func TestServicePropagatesStoreErrors(t *testing.T) {
	t.Parallel()

	store := &sessionStoreStub{getErr: errors.New("boom")}
	svc := Must[testPayload](Options[testPayload]{Store: store})

	_, err := svc.Load(context.Background(), "sess-1")
	require.ErrorIs(t, err, store.getErr)
}
