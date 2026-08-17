package userconfirmationservice_test

import (
	"context"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/local/confirmation"
	"github.com/assurrussa/goauth/internal/legacy/service/userconfirmationservice"
	"github.com/assurrussa/goauth/internal/legacy/shared"
)

type repoStub struct{}

func (repoStub) GetBySubjectID(_ context.Context, _ authcore.SubjectID) ([]confirmation.Record, error) {
	return []confirmation.Record{}, nil
}

func (repoStub) IsConfirmed(
	_ context.Context,
	_ authcore.SubjectID,
	_ confirmation.Type,
	_ confirmation.Purpose,
) (bool, error) {
	return true, nil
}

func (repoStub) GetConfirmationStatus(_ context.Context, _ authcore.SubjectID) (confirmation.Status, error) {
	return confirmation.Status{
		EmailConfirmed: true,
	}, nil
}

func TestPublicSurface(t *testing.T) {
	t.Parallel()

	service, err := userconfirmationservice.New(userconfirmationservice.NewOptions(
		logger.Discard(),
		repoStub{},
	))
	require.NoError(t, err)

	subjectID := shared.NewSubjectID()
	status, err := service.GetUserConfirmationStatus(context.Background(), subjectID)
	require.NoError(t, err)
	require.True(t, status.EmailConfirmed)

	confirmed, err := service.IsUserConfirmed(
		context.Background(),
		subjectID,
		shared.ConfirmationTypeEmail,
		shared.ConfirmationPurposeConfirmation,
	)
	require.NoError(t, err)
	require.True(t, confirmed)
}
