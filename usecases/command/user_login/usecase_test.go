package userlogin_test

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

	authcore "github.com/assurrussa/goauth/core"
	authshared "github.com/assurrussa/goauth/shared"
	userlogin "github.com/assurrussa/goauth/usecases/command/user_login"
	userloginmocks "github.com/assurrussa/goauth/usecases/command/user_login/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl            *gomock.Controller
	authServiceMock *userloginmocks.MockauthService

	useCase *userlogin.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		authServiceMock := userloginmocks.NewMockauthService(ctrl)

		return &TestUseCaseSuite{
			ctrl:            ctrl,
			authServiceMock: authServiceMock,
			useCase:         userlogin.Must(userlogin.NewOptions(logger.Discard(), authServiceMock)),
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		userlogin.Must(userlogin.NewOptions(nil, nil))
	})
}

func TestUseCase_Error(t *testing.T) {
	h, err := userlogin.New(userlogin.NewOptions(nil, nil))
	require.Error(t, err)
	assert.Empty(t, h)
}

func TestUseCase_Execute_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	expectToken := &authcore.TokenPair{
		SubjectID:        authshared.NewSubjectID(),
		RefreshToken:     "refresh_token",
		AccessToken:      "access_token",
		ExpiresIn:        1,
		ExpiresRefreshIn: 6,
	}
	dto := userlogin.Request{
		ID:       sharedtypes.NewRequestID(),
		Email:    "test@test.com",
		Password: "password",
	}
	ts.authServiceMock.EXPECT().Login(ctx, dto.Email, dto.Password).
		Return(expectToken, nil).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	require.NoError(t, err)
	assert.Equal(t, expectToken.AccessToken, res.AccessToken)
	assert.Equal(t, expectToken.RefreshToken, res.RefreshToken)
	assert.Equal(t, expectToken.ExpiresIn, res.ExpiresIn)
	assert.Equal(t, expectToken.ExpiresRefreshIn, res.ExpiresRefreshIn)
}

func TestUseCase_Execute_AuthServiceError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	errExpected := errors.New("expected error")
	dto := userlogin.Request{
		ID:       sharedtypes.NewRequestID(),
		Email:    "test@test.com",
		Password: "password",
	}
	ts.authServiceMock.EXPECT().Login(ctx, dto.Email, dto.Password).
		Return(nil, errExpected).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	require.Error(t, err)
	require.ErrorIs(t, err, errExpected)
	assert.Empty(t, res)
}

func TestUseCase_Execute_ValidateError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	dto := userlogin.Request{}

	res, err := ts.useCase.Handle(ctx, dto)
	require.Error(t, err)
	assert.Empty(t, res)
}
