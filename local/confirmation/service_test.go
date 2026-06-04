package confirmation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	notificationsjob "github.com/assurrussa/goauth/infrastructure/notify/notifications"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/shared"
)

type codeRepoStub struct {
	active         CodeRecord
	activeErr      error
	last           *CodeRecord
	upserted       CodeRecord
	verified       CodeRecord
	incrementedID  int64
	usageWindow    UsageWindow
	cleanupDeleted int64
}

func (s *codeRepoStub) UpsertCode(_ context.Context, record CodeRecord) (int64, error) {
	s.upserted = record
	s.active = record
	s.active.ID = 10
	return 10, nil
}

func (s *codeRepoStub) GetActiveCodeBySubjectAndType(
	_ context.Context,
	_ shared.SubjectID,
	_ Type,
	_ Purpose,
) (CodeRecord, error) {
	if s.activeErr != nil {
		return CodeRecord{}, s.activeErr
	}
	return s.active, nil
}

func (s *codeRepoStub) UpdateVerified(_ context.Context, record CodeRecord) error {
	s.verified = record
	return nil
}

func (s *codeRepoStub) IncrementAttempts(_ context.Context, id int64) error {
	s.incrementedID = id
	return nil
}

func (s *codeRepoStub) FindLast(_ context.Context, _ shared.SubjectID, _ Type) (*CodeRecord, error) {
	if s.last == nil {
		return nil, errors.New("not found")
	}
	return s.last, nil
}

func (s *codeRepoStub) CountSince(_ context.Context, _ shared.SubjectID, _ Type, _ time.Time) (UsageWindow, error) {
	return s.usageWindow, nil
}

func (s *codeRepoStub) CleanupExpiredCodes(_ context.Context, _ int, _ int) (int64, error) {
	return s.cleanupDeleted, nil
}

type recordRepoStub struct {
	status    Status
	records   []Record
	confirmed bool
	upserted  Record
}

func (s *recordRepoStub) Upsert(_ context.Context, record Record) (int64, error) {
	s.upserted = record
	return 1, nil
}

func (s *recordRepoStub) IsConfirmed(_ context.Context, _ shared.SubjectID, _ Type, _ Purpose) (bool, error) {
	return s.confirmed, nil
}

func (s *recordRepoStub) GetConfirmationStatus(_ context.Context, _ shared.SubjectID) (Status, error) {
	return s.status, nil
}

func (s *recordRepoStub) GetBySubjectID(_ context.Context, _ shared.SubjectID) ([]Record, error) {
	return s.records, nil
}

type subjectUpdaterStub struct {
	appliedType Type
	appliedAt   time.Time
}

func (s *subjectUpdaterStub) ApplyConfirmation(_ context.Context, _ shared.SubjectID, confirmationType Type, confirmedAt time.Time) error {
	s.appliedType = confirmationType
	s.appliedAt = confirmedAt
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

func TestGenerateVerifyAndStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 18, 20, 30, 0, 0, time.UTC)
	subjectID := shared.MustParse[shared.SubjectID]("123e4567-e89b-12d3-a456-426614174105")
	codeRepo := &codeRepoStub{
		usageWindow: UsageWindow{},
	}
	recordRepo := &recordRepoStub{
		status: Status{EmailConfirmed: true},
		records: []Record{
			{SubjectID: subjectID, ConfirmationType: TypeEmail, Purpose: PurposeConfirmation},
		},
	}
	subjects := &subjectUpdaterStub{}
	outbox := &outboxStub{}

	service, err := New(Options{
		CodeRepo:       codeRepo,
		RecordRepo:     recordRepo,
		Subjects:       subjects,
		Outbox:         outbox,
		CodeExpiration: time.Hour,
		Now:            func() time.Time { return now },
		GenerateCode:   func() (Code, error) { return Code("123456"), nil },
	})
	require.NoError(t, err)

	err = service.GenerateAndSaveCode(context.Background(), subjectID, TypeEmail, PurposeConfirmation, "user@example.com")
	require.NoError(t, err)
	require.Equal(t, "user@example.com", codeRepo.upserted.ConfirmationInfo)
	require.Equal(t, 1, outbox.calls)

	err = service.VerifyCode(context.Background(), subjectID, Code("123456"), TypeEmail, PurposeConfirmation)
	require.NoError(t, err)
	require.Equal(t, TypeEmail, subjects.appliedType)
	require.Equal(t, TypeEmail, recordRepo.upserted.ConfirmationType)

	status, err := service.GetConfirmationStatus(context.Background(), subjectID)
	require.NoError(t, err)
	require.True(t, status.EmailConfirmed)

	records, err := service.GetConfirmations(context.Background(), subjectID)
	require.NoError(t, err)
	require.Len(t, records, 1)
}

func TestVerifyCodeInvalidIncrementsAttempts(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 18, 20, 30, 0, 0, time.UTC)
	subjectID := shared.MustParse[shared.SubjectID]("123e4567-e89b-12d3-a456-426614174105")
	codeRepo := &codeRepoStub{
		active: CodeRecord{
			ID:               9,
			SubjectID:        subjectID,
			Code:             Code("123456"),
			ConfirmationType: TypeEmail,
			Purpose:          PurposeConfirmation,
			ExpiresAt:        now.Add(30 * time.Minute),
		},
	}

	service, err := New(Options{
		CodeRepo:     codeRepo,
		RecordRepo:   &recordRepoStub{},
		Subjects:     &subjectUpdaterStub{},
		Outbox:       &outboxStub{},
		MaxAttempts:  5,
		Now:          func() time.Time { return now },
		GenerateCode: func() (Code, error) { return Code("123456"), nil },
	})
	require.NoError(t, err)

	err = service.VerifyCode(context.Background(), subjectID, Code("000000"), TypeEmail, PurposeConfirmation)
	require.ErrorIs(t, err, ErrInvalidCode)
	require.Equal(t, int64(9), codeRepo.incrementedID)
}
