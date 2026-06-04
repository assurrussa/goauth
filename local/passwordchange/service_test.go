package passwordchange

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/core"
	notificationsjob "github.com/assurrussa/goauth/infrastructure/notify/notifications"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

type lookupStub struct {
	subject authcore.Subject
	err     error
}

func (s lookupStub) GetByID(_ context.Context, _ authcore.SubjectID) (authcore.Subject, error) {
	return s.subject, s.err
}

type writerStub struct {
	updatedSubject authcore.Subject
	updatedHash    string
	err            error
}

func (s *writerStub) CreateUser(context.Context, authcore.Subject) (authcore.Subject, error) {
	panic("unexpected CreateUser call")
}

func (s *writerStub) UpdatePassword(_ context.Context, subject authcore.Subject, passwordHash string) error {
	s.updatedSubject = subject
	s.updatedHash = passwordHash
	return s.err
}

type hasherStub struct {
	compare map[string]error
	hash    []byte
	hashErr error
}

func (s hasherStub) GenerateHash(password string) ([]byte, error) {
	return append([]byte(nil), s.hash...), s.hashErr
}

func (s hasherStub) CompareHash(passwordHash string, password string) error {
	if err, ok := s.compare[password]; ok {
		return err
	}
	return assert.AnError
}

type outboxStub struct {
	name      string
	payload   string
	available time.Time
	err       error
}

func (s *outboxStub) Put(
	_ context.Context,
	name,
	payload string,
	available time.Time,
) (outbox.JobID, error) {
	s.name = name
	s.payload = payload
	s.available = available
	return outbox.NewJobID(), s.err
}

func TestChangePassword(t *testing.T) {
	t.Parallel()

	subject := authcore.Subject{
		ID:           authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174010"),
		Kind:         authcore.SubjectKindAccount,
		NumericID:    10,
		PasswordHash: "current-hash",
	}

	writer := &writerStub{}
	service, err := New(Options{
		Lookup: lookupStub{subject: subject},
		Writer: writer,
		Hasher: hasherStub{
			compare: map[string]error{
				"bad-current":      assert.AnError,
				"current-password": nil,
				"next-password":    assert.AnError,
			},
			hash: []byte("next-hash"),
		},
	})
	require.NoError(t, err)

	err = service.Change(context.Background(), subject.ID, "bad-current", "next-password")
	require.ErrorIs(t, err, ErrInvalidCurrentPassword)

	err = service.Change(context.Background(), subject.ID, "current-password", "current-password")
	require.ErrorIs(t, err, ErrPasswordIsEqualCurrentPassword)

	err = service.Change(context.Background(), subject.ID, "current-password", "next-password")
	require.NoError(t, err)
	require.Equal(t, subject.ID, writer.updatedSubject.ID)
	require.Equal(t, "next-hash", writer.updatedHash)
}

func TestChangePasswordEnqueuesSuccessNotification(t *testing.T) {
	t.Parallel()

	subject := authcore.Subject{
		ID:           authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174011"),
		Kind:         authcore.SubjectKindAccount,
		Email:        "user@example.com",
		PasswordHash: "current-hash",
	}
	outbox := &outboxStub{}

	service, err := New(Options{
		Lookup: lookupStub{subject: subject},
		Writer: &writerStub{},
		Hasher: hasherStub{
			compare: map[string]error{
				"current-password": nil,
				"next-password":    assert.AnError,
			},
			hash: []byte("next-hash"),
		},
		Outbox: outbox,
	})
	require.NoError(t, err)

	err = service.Change(context.Background(), subject.ID, "current-password", "next-password")
	require.NoError(t, err)

	require.Equal(t, notificationsjob.JobName, outbox.name)
	payload, err := notificationsjob.UnmarshalPayload(outbox.payload)
	require.NoError(t, err)
	require.Equal(t, "user@example.com", payload.To)
	require.Equal(t, "password_change_success", payload.Template)
	require.Equal(t, "user@example.com", payload.Metadata["email"])
	require.False(t, outbox.available.IsZero())
}
