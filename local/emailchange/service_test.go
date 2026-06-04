package emailchange

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/core"
	notificationsjob "github.com/assurrussa/goauth/infrastructure/notify/notifications"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

type storeStub struct {
	req            Request
	getErr         error
	upserted       Request
	deletedSubject string
	incremented    string
}

func (s *storeStub) Upsert(_ context.Context, subjectID string, req Request) error {
	s.upserted = req
	s.req = req
	s.getErr = nil
	return nil
}

func (s *storeStub) Get(_ context.Context, subjectID string, _ bool) (Request, error) {
	if s.getErr != nil {
		return Request{}, s.getErr
	}
	return s.req, nil
}

func (s *storeStub) IncrementAttempts(_ context.Context, subjectID string) error {
	s.incremented = subjectID
	s.req.Attempts++
	return nil
}

func (s *storeStub) Delete(_ context.Context, subjectID string) error {
	s.deletedSubject = subjectID
	return nil
}

type repoStub struct {
	byEmail        map[string]authcore.Subject
	updatedID      string
	updatedEmail   string
	markedID       string
	updateEmailErr error
}

func (s *repoStub) GetByEmail(_ context.Context, email string) (authcore.Subject, error) {
	return s.byEmail[email], nil
}

func (s *repoStub) UpdateEmail(_ context.Context, subjectID, email string) error {
	s.updatedID = subjectID
	s.updatedEmail = email
	return s.updateEmailErr
}

func (s *repoStub) MarkEmailConfirmed(_ context.Context, subjectID string, _ time.Time) error {
	s.markedID = subjectID
	return nil
}

type outboxStub struct {
	calls int
}

func (s *outboxStub) Put(_ context.Context, name, payload string, _ time.Time) (outbox.JobID, error) {
	if name != notificationsjob.JobName || payload == "" {
		return outbox.JobID{}, errors.New("unexpected outbox payload")
	}
	s.calls++
	return outbox.NewJobID(), nil
}

func TestRequestAndConfirmEmailChange(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 18, 20, 0, 0, 0, time.UTC)
	store := &storeStub{getErr: ErrNotFound}
	repo := &repoStub{
		byEmail: map[string]authcore.Subject{},
	}
	outbox := &outboxStub{}

	service, err := New(Options{
		Store:   store,
		Repo:    repo,
		Outbox:  outbox,
		CodeGen: func() (string, error) { return "123456", nil },
		TTL:     15 * time.Minute,
		Now:     func() time.Time { return now },
	})
	require.NoError(t, err)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174020")

	subject := authcore.Subject{
		ID:    subjectID,
		Kind:  authcore.SubjectKindAccount,
		Email: "old@example.com",
	}

	err = service.Request(context.Background(), subject, "new@example.com", "127.0.0.1")
	require.NoError(t, err)
	require.Equal(t, "new@example.com", store.upserted.NewEmail)
	require.Equal(t, 2, outbox.calls)

	newEmail, err := service.Confirm(context.Background(), subject, "123456")
	require.NoError(t, err)
	require.Equal(t, "new@example.com", newEmail)
	require.Equal(t, subjectID.String(), repo.updatedID)
	require.Equal(t, "new@example.com", repo.updatedEmail)
	require.Equal(t, subjectID.String(), repo.markedID)
	require.Equal(t, subjectID.String(), store.deletedSubject)
}

func TestConfirmEmailChangeInvalidCode(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 18, 20, 0, 0, 0, time.UTC)
	store := &storeStub{
		req: Request{
			OldEmail:  "old@example.com",
			NewEmail:  "new@example.com",
			Code:      "123456",
			ExpiresAt: now.Add(10 * time.Minute),
			UpdatedAt: now.Add(-time.Minute),
		},
	}

	service, err := New(Options{
		Store:  store,
		Repo:   &repoStub{},
		Outbox: &outboxStub{},
		Now:    func() time.Time { return now },
	})
	require.NoError(t, err)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174021")

	_, err = service.Confirm(context.Background(), authcore.Subject{ID: subjectID, Email: "old@example.com"}, "000000")
	require.ErrorIs(t, err, ErrInvalidCode)
	require.Equal(t, subjectID.String(), store.incremented)
}
