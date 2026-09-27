package usertokenrefresh_test

import (
	"context"
	"errors"
	"testing"

	logger "github.com/assurrussa/gologger"
	"github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	authshared "github.com/assurrussa/goauth/internal/legacy/shared"
	usertokenrefresh "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_token_refresh"
	usertokenrefreshmocks "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_token_refresh/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl            *gomock.Controller
	authServiceMock *usertokenrefreshmocks.MockauthService

	useCase *usertokenrefresh.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		authServiceMock := usertokenrefreshmocks.NewMockauthService(ctrl)

		return &TestUseCaseSuite{
			ctrl:            ctrl,
			authServiceMock: authServiceMock,
			useCase:         usertokenrefresh.Must(usertokenrefresh.NewOptions(logger.Discard(), authServiceMock)),
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		usertokenrefresh.Must(usertokenrefresh.NewOptions(nil, nil))
	})
}

func TestUseCase_Error(t *testing.T) {
	h, err := usertokenrefresh.New(usertokenrefresh.NewOptions(nil, nil))
	require.Error(t, err)
	assert.Empty(t, h)
}

func TestUseCase_Handle_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	expectToken := &authcore.TokenPair{
		SubjectID:        authshared.NewSubjectID(),
		RefreshToken:     "refresh_token",
		AccessToken:      "access_token",
		ExpiresIn:        1,
		ExpiresRefreshIn: 2,
	}
	//nolint:gosec // testing token
	dto := usertokenrefresh.Request{
		ID:           sharedtypes.NewRequestID(),
		RefreshToken: "awrwqrwqrqwrwqrqwrwq",
	}
	ts.authServiceMock.EXPECT().RefreshToken(ctx, dto.RefreshToken).
		Return(expectToken, nil).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	require.NoError(t, err)
	assert.Equal(t, expectToken.SubjectID, res.SubjectID)
	assert.Equal(t, expectToken.AccessToken, res.AccessToken)
	assert.Equal(t, expectToken.RefreshToken, res.RefreshToken)
	assert.Equal(t, expectToken.ExpiresIn, res.ExpiresIn)
	assert.Equal(t, expectToken.ExpiresRefreshIn, res.ExpiresRefreshIn)
}

func TestUseCase_Handle_AuthServiceError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	errExpected := errors.New("expected error")
	//nolint:gosec // testing token
	dto := usertokenrefresh.Request{
		ID:           sharedtypes.NewRequestID(),
		RefreshToken: "awrwqrwqrqwrwqrqwrwq",
	}
	ts.authServiceMock.EXPECT().RefreshToken(ctx, dto.RefreshToken).
		Return(nil, errExpected).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	require.Error(t, err)
	require.ErrorIs(t, err, errExpected)
	assert.Empty(t, res)
}

func TestUseCase_Handle_ValidateError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	dto := usertokenrefresh.Request{}

	res, err := ts.useCase.Handle(ctx, dto)
	require.Error(t, err)
	assert.Empty(t, res)
}
