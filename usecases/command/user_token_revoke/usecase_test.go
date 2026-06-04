package usertokenrevoke_test

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	authshared "github.com/assurrussa/goauth/shared"
	usertokenrevoke "github.com/assurrussa/goauth/usecases/command/user_token_revoke"
	usertokenrevokemocks "github.com/assurrussa/goauth/usecases/command/user_token_revoke/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl            *gomock.Controller
	authServiceMock *usertokenrevokemocks.MockauthService

	useCase *usertokenrevoke.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		authServiceMock := usertokenrevokemocks.NewMockauthService(ctrl)

		useCase := usertokenrevoke.Must(usertokenrevoke.NewOptions(
			logger.Discard(),
			authServiceMock,
		))

		return &TestUseCaseSuite{
			ctrl:            ctrl,
			authServiceMock: authServiceMock,
			useCase:         useCase,
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		usertokenrevoke.Must(usertokenrevoke.NewOptions(nil, nil))
	})
}

func TestUseCase_Handle_Success(t *testing.T) {
	ctx, cancel, ts := NewTestUseCaseSuite(t)
	defer cancel()

	tokenID := int64(123)
	const currentToken = "current_token"
	subjectID := authshared.NewSubjectID()

	// Define request
	req := usertokenrevoke.Request{
		ID:           sharedtypes.NewRequestID(),
		SubjectID:    subjectID,
		TokenID:      tokenID,
		CurrentToken: currentToken,
	}

	// Mock the auth service to return success
	ts.authServiceMock.EXPECT().RevokeTokenByID(ctx, subjectID, tokenID).
		Return(true, nil).
		Times(1)

	// Handle the use case
	res, err := ts.useCase.Handle(ctx, req)

	// Verify results
	require.NoError(t, err)
	assert.True(t, res.Success)
}

func TestUseCase_Handle_AuthServiceError(t *testing.T) {
	ctx, cancel, ts := NewTestUseCaseSuite(t)
	defer cancel()

	tokenID := int64(123)
	currentToken := "current_token"
	expectedErr := errors.New("token revocation failed")
	subjectID := authshared.NewSubjectID()

	// Define request
	req := usertokenrevoke.Request{
		ID:           sharedtypes.NewRequestID(),
		SubjectID:    subjectID,
		TokenID:      tokenID,
		CurrentToken: currentToken,
	}

	// Mock the auth service to return an error
	ts.authServiceMock.EXPECT().RevokeTokenByID(ctx, subjectID, tokenID).
		Return(false, expectedErr).
		Times(1)

	// Handle the use case
	res, err := ts.useCase.Handle(ctx, req)

	// Verify error is returned
	require.Error(t, err)
	require.ErrorIs(t, err, expectedErr)
	assert.False(t, res.Success)
}

func TestUseCase_Handle_ValidationError(t *testing.T) {
	ctx, cancel, ts := NewTestUseCaseSuite(t)
	defer cancel()

	// Create an invalid request with missing required fields
	req := usertokenrevoke.Request{
		// Missing required fields
	}

	// Handle the use case with invalid request
	res, err := ts.useCase.Handle(ctx, req)

	// Verify validation error is returned
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate request")
	assert.False(t, res.Success)
}

func TestUseCase_Handle_TokenDoesNotBelongToUser(t *testing.T) {
	ctx, cancel, ts := NewTestUseCaseSuite(t)
	defer cancel()

	tokenID := int64(123)
	currentToken := "current_token"
	expectedErr := errors.New("token does not belong to the user")
	subjectID := authshared.NewSubjectID()

	// Define request
	req := usertokenrevoke.Request{
		ID:           sharedtypes.NewRequestID(),
		SubjectID:    subjectID,
		TokenID:      tokenID,
		CurrentToken: currentToken,
	}

	// Mock the auth service to return a specific error
	ts.authServiceMock.EXPECT().RevokeTokenByID(ctx, subjectID, tokenID).
		Return(false, expectedErr).
		Times(1)

	// Handle the use case
	res, err := ts.useCase.Handle(ctx, req)

	// Verify error is returned
	require.Error(t, err)
	require.ErrorIs(t, err, expectedErr)
	assert.False(t, res.Success)
}
