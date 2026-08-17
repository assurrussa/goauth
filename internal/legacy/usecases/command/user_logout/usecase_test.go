package userlogout_test

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
	userlogout "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_logout"
	userlogoutmocks "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_logout/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl            *gomock.Controller
	authServiceMock *userlogoutmocks.MockauthService

	useCase *userlogout.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		authServiceMock := userlogoutmocks.NewMockauthService(ctrl)

		return &TestUseCaseSuite{
			ctrl:            ctrl,
			authServiceMock: authServiceMock,
			useCase:         userlogout.Must(userlogout.NewOptions(logger.Discard(), authServiceMock)),
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		userlogout.Must(userlogout.NewOptions(nil, nil))
	})
}

func TestUseCase_Error(t *testing.T) {
	h, err := userlogout.New(userlogout.NewOptions(nil, nil))
	require.Error(t, err)
	assert.Empty(t, h)
}

func TestUseCase_Execute_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	subjectID := authshared.NewSubjectID()
	dto := userlogout.Request{
		ID:           sharedtypes.NewRequestID(),
		SubjectID:    subjectID,
		RefreshToken: "refresh_token",
	}
	ts.authServiceMock.EXPECT().DeleteRefreshToken(ctx, subjectID, dto.RefreshToken).
		Return(nil).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	ts.Require().NoError(err)
	ts.Empty(res)
}

func TestUseCase_Execute_AuthServiceError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	errExpected := errors.New("expected error")
	subjectID := authshared.NewSubjectID()
	dto := userlogout.Request{
		ID:           sharedtypes.NewRequestID(),
		SubjectID:    subjectID,
		RefreshToken: "refresh_token",
	}
	ts.authServiceMock.EXPECT().DeleteRefreshToken(ctx, subjectID, dto.RefreshToken).
		Return(errExpected).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	ts.Require().Error(err)
	ts.Require().ErrorIs(err, errExpected)
	ts.Empty(res)
}

func TestUseCase_Execute_ValidateError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	dto := userlogout.Request{}

	res, err := ts.useCase.Handle(ctx, dto)
	ts.Require().Error(err)
	ts.Empty(res)
}
