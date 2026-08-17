package userlogoutall_test

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

	authshared "github.com/assurrussa/goauth/internal/legacy/shared"
	userlogoutall "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_logout_all"
	userlogoutallmocks "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_logout_all/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl            *gomock.Controller
	authServiceMock *userlogoutallmocks.MockauthService

	useCase *userlogoutall.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		authServiceMock := userlogoutallmocks.NewMockauthService(ctrl)

		return &TestUseCaseSuite{
			ctrl:            ctrl,
			authServiceMock: authServiceMock,
			useCase:         userlogoutall.Must(userlogoutall.NewOptions(logger.Discard(), authServiceMock)),
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		userlogoutall.Must(userlogoutall.NewOptions(nil, nil))
	})
}

func TestUseCase_Execute_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	subjectID := authshared.NewSubjectID()
	currentToken := "current_refresh_token"
	expectedCount := int64(3)

	dto := userlogoutall.Request{
		ID:             sharedtypes.NewRequestID(),
		SubjectID:      subjectID,
		CurrentSession: currentToken,
	}

	ts.authServiceMock.EXPECT().
		DeleteUserRefreshTokensExcept(ctx, subjectID, currentToken).
		Return(expectedCount, nil).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	require.NoError(t, err)
	assert.Equal(t, expectedCount, res.TokensDeleted)
}

func TestUseCase_Execute_AuthServiceError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	errExpected := errors.New("expected error")
	subjectID := authshared.NewSubjectID()
	currentToken := "current_refresh_token"

	dto := userlogoutall.Request{
		ID:             sharedtypes.NewRequestID(),
		SubjectID:      subjectID,
		CurrentSession: currentToken,
	}

	ts.authServiceMock.EXPECT().
		DeleteUserRefreshTokensExcept(ctx, subjectID, currentToken).
		Return(int64(0), errExpected).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	require.Error(t, err)
	require.ErrorIs(t, err, errExpected)
	assert.Equal(t, int64(0), res.TokensDeleted)
}

func TestUseCase_Execute_ValidateError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	dto := userlogoutall.Request{}

	res, err := ts.useCase.Handle(ctx, dto)
	require.Error(t, err)
	assert.Equal(t, int64(0), res.TokensDeleted)
}
