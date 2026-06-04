package emailchangeservice_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/core"
	notificationsjob "github.com/assurrussa/goauth/infrastructure/notify/notifications"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	emailchangeservice "github.com/assurrussa/goauth/service/emailchangeservice"
)

type storeStub struct {
	req emailchangeservice.Request
	err error
}

func (s *storeStub) Upsert(_ context.Context, _ int64, req emailchangeservice.Request) error {
	s.req = req
	s.err = nil
	return nil
}

func (s *storeStub) Get(_ context.Context, _ int64, _ bool) (emailchangeservice.Request, error) {
	if s.err != nil {
		return emailchangeservice.Request{}, s.err
	}
	return s.req, nil
}

func (s *storeStub) IncrementAttempts(_ context.Context, _ int64) error { return nil }
func (s *storeStub) Delete(_ context.Context, _ int64) error            { return nil }

type repoStub struct {
	subject emailchangeservice.Subject[int64]
}

func (s repoStub) GetByEmail(_ context.Context, _ string) (emailchangeservice.Subject[int64], error) {
	return s.subject, nil
}

func (s repoStub) UpdateEmail(_ context.Context, _ int64, _ string) error {
	return nil
}

type outboxStub struct{}

func (outboxStub) Put(_ context.Context, name, payload string, _ time.Time) (outbox.JobID, error) {
	if name != notificationsjob.JobName || payload == "" {
		return outbox.JobID{}, context.Canceled
	}
	return outbox.NewJobID(), nil
}

func TestNewServiceAndPending(t *testing.T) {
	t.Parallel()

	store := &storeStub{err: emailchangeservice.ErrNotFound}
	service, err := emailchangeservice.NewService(emailchangeservice.Options[int64]{
		Store:    store,
		Repo:     repoStub{},
		Outbox:   outboxStub{},
		IsZeroID: func(id int64) bool { return id == 0 },
		CodeGen:  func() (string, error) { return "123456", nil },
	})
	require.NoError(t, err)

	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174118")
	err = service.Request(context.Background(), emailchangeservice.Subject[int64]{
		ID:          42,
		CanonicalID: subjectID,
		Email:       "old@example.com",
	}, "new@example.com", "127.0.0.1")
	require.NoError(t, err)

	pending, err := service.GetPending(context.Background(), 42)
	require.NoError(t, err)
	require.Equal(t, "new@example.com", pending.NewEmail)
}
