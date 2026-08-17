package confirmationcodeservice_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/assurrussa/goshared/pkg/logger"
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/infrastructure/notify"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
	"github.com/assurrussa/goauth/internal/legacy/local/confirmation"
	"github.com/assurrussa/goauth/internal/legacy/service/confirmationcodeservice"
	"github.com/assurrussa/goauth/internal/legacy/shared"
)

type codeRepoStub struct {
	records map[string]confirmation.CodeRecord
}

func newCodeRepoStub() *codeRepoStub {
	return &codeRepoStub{records: make(map[string]confirmation.CodeRecord)}
}

func (r *codeRepoStub) key(subjectID authcore.SubjectID, codeType confirmation.Type, purpose confirmation.Purpose) string {
	return subjectID.String() + "|" + codeType.String() + "|" + purpose.String()
}

func (r *codeRepoStub) UpsertCode(_ context.Context, record confirmation.CodeRecord) (int64, error) {
	if record.ID == 0 {
		record.ID = int64(len(r.records) + 1)
	}
	r.records[r.key(record.SubjectID, record.ConfirmationType, record.Purpose)] = record
	return record.ID, nil
}

func (r *codeRepoStub) GetActiveCodeBySubjectAndType(
	_ context.Context,
	subjectID authcore.SubjectID,
	codeType confirmation.Type,
	purpose confirmation.Purpose,
) (confirmation.CodeRecord, error) {
	record, ok := r.records[r.key(subjectID, codeType, purpose)]
	if !ok {
		return confirmation.CodeRecord{}, errors.New("not found")
	}
	return record, nil
}

func (r *codeRepoStub) UpdateVerified(_ context.Context, record confirmation.CodeRecord) error {
	current := r.records[r.key(record.SubjectID, record.ConfirmationType, record.Purpose)]
	current.VerifiedAt = record.VerifiedAt
	r.records[r.key(record.SubjectID, record.ConfirmationType, record.Purpose)] = current
	return nil
}

func (r *codeRepoStub) IncrementAttempts(_ context.Context, id int64) error {
	for key, record := range r.records {
		if record.ID == id {
			record.Attempts++
			r.records[key] = record
			return nil
		}
	}
	return nil
}

func (r *codeRepoStub) FindLast(
	_ context.Context,
	subjectID authcore.SubjectID,
	targetType confirmation.Type,
) (*confirmation.CodeRecord, error) {
	for _, record := range r.records {
		if record.SubjectID == subjectID && record.ConfirmationType == targetType {
			recordCopy := record
			return &recordCopy, nil
		}
	}
	return nil, errors.New("not found")
}

func (r *codeRepoStub) CountSince(
	_ context.Context,
	_ authcore.SubjectID,
	_ confirmation.Type,
	_ time.Time,
) (confirmation.UsageWindow, error) {
	return confirmation.UsageWindow{}, nil
}

func (r *codeRepoStub) CleanupExpiredCodes(_ context.Context, _ int, _ int) (int64, error) {
	return 0, nil
}

type recordRepoStub struct {
	records []confirmation.Record
}

func (r *recordRepoStub) Upsert(_ context.Context, record confirmation.Record) (int64, error) {
	if record.ID == 0 {
		record.ID = int64(len(r.records) + 1)
	}
	r.records = append(r.records, record)
	return record.ID, nil
}

func (r *recordRepoStub) IsConfirmed(
	_ context.Context,
	subjectID authcore.SubjectID,
	confirmationType confirmation.Type,
	purpose confirmation.Purpose,
) (bool, error) {
	for _, record := range r.records {
		if record.SubjectID == subjectID && record.ConfirmationType == confirmationType && record.Purpose == purpose {
			return true, nil
		}
	}
	return false, nil
}

func (r *recordRepoStub) GetConfirmationStatus(_ context.Context, subjectID authcore.SubjectID) (confirmation.Status, error) {
	status := confirmation.Status{}
	for _, record := range r.records {
		if record.SubjectID != subjectID {
			continue
		}
		switch record.ConfirmationType {
		case confirmation.TypeEmail:
			status.EmailConfirmed = true
		case confirmation.TypePhone:
			status.PhoneConfirmed = true
		case confirmation.TypeUnknown:
			break
		case confirmation.TypeTgBot:
			status.TelegramConfirmed = true
		}
	}
	return status, nil
}

func (r *recordRepoStub) GetBySubjectID(_ context.Context, subjectID authcore.SubjectID) ([]confirmation.Record, error) {
	result := make([]confirmation.Record, 0, len(r.records))
	for _, record := range r.records {
		if record.SubjectID == subjectID {
			result = append(result, record)
		}
	}
	return result, nil
}

type profileStoreStub struct {
	users map[authcore.SubjectID]authcore.Profile
}

func (r *profileStoreStub) GetBySubjectID(_ context.Context, subjectID authcore.SubjectID) (authcore.Profile, error) {
	return r.users[subjectID], nil
}

func (r *profileStoreStub) MarkEmailConfirmed(_ context.Context, subjectID authcore.SubjectID, updateAt time.Time) error {
	user := r.users[subjectID]
	user.ConfirmedEmailAt.Time = updateAt
	user.ConfirmedEmailAt.Valid = true
	r.users[subjectID] = user
	return nil
}

func (r *profileStoreStub) MarkPhoneConfirmed(_ context.Context, subjectID authcore.SubjectID, updateAt time.Time) error {
	user := r.users[subjectID]
	user.ConfirmedPhoneAt.Time = updateAt
	user.ConfirmedPhoneAt.Valid = true
	r.users[subjectID] = user
	return nil
}

func (r *profileStoreStub) UpdateEmail(_ context.Context, subjectID authcore.SubjectID, email string) error {
	user := r.users[subjectID]
	user.Email = email
	r.users[subjectID] = user
	return nil
}

type outboxStub struct{}

func (outboxStub) Put(_ context.Context, _ string, _ string, _ time.Time) (outbox.JobID, error) {
	var id outbox.JobID
	return id, nil
}

type notificationStub struct{}

func (notificationStub) SendToChannel(
	_ context.Context,
	_ notify.NotificationChannel,
	_ *notify.Notification,
	_ ...*notify.Recipient,
) ([]*notify.NotificationResult, error) {
	return nil, nil
}

func TestGenerateVerifyAndReadConfirmationInfo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	userID := sharedtypes.NewUserID()
	subjectID := shared.NewSubjectID()
	profiles := &profileStoreStub{
		users: map[authcore.SubjectID]authcore.Profile{
			subjectID: {
				PublicID: userID,
				Email:    "user@example.com",
			},
		},
	}
	codeRepo := newCodeRepoStub()
	recordRepo := &recordRepoStub{}

	service := confirmationcodeservice.Must(confirmationcodeservice.NewOptions(
		notificationStub{},
		codeRepo,
		profiles,
		profiles,
		profiles,
		recordRepo,
		logger.Discard(),
		outboxStub{},
	))

	err := service.GenerateAndSaveCode(
		ctx,
		subjectID,
		shared.ConfirmationTypeEmail,
		shared.ConfirmationPurposeConfirmation,
		"user@example.com",
	)
	require.NoError(t, err)

	record, err := codeRepo.GetActiveCodeBySubjectAndType(
		ctx,
		subjectID,
		confirmation.TypeEmail,
		confirmation.PurposeConfirmation,
	)
	require.NoError(t, err)

	err = service.VerifyCode(
		ctx,
		subjectID,
		shared.ConfirmCode(record.Code.String()),
		shared.ConfirmationTypeEmail,
		shared.ConfirmationPurposeConfirmation,
	)
	require.NoError(t, err)

	info, err := service.GetConfirmationInfo(ctx, subjectID)
	require.NoError(t, err)
	require.True(t, info.Status.EmailConfirmed)
	require.True(t, info.Profile.ConfirmedEmailAt.Valid)
	require.Equal(t, "user@example.com", info.Profile.Email)
}
