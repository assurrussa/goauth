package usertokenban_test

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

	authshared "github.com/assurrussa/goauth/internal/legacy/shared"
	usertokenban "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_token_ban"
	usertokenbanmocks "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_token_ban/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl            *gomock.Controller
	authServiceMock *usertokenbanmocks.MockauthService

	useCase *usertokenban.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		authServiceMock := usertokenbanmocks.NewMockauthService(ctrl)

		return &TestUseCaseSuite{
			ctrl:            ctrl,
			authServiceMock: authServiceMock,
			useCase:         usertokenban.Must(usertokenban.NewOptions(logger.Discard(), authServiceMock)),
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		usertokenban.Must(usertokenban.NewOptions(nil, nil))
	})
}

func TestUseCase_Error(t *testing.T) {
	h, err := usertokenban.New(usertokenban.NewOptions(nil, nil))
	require.Error(t, err)
	assert.Empty(t, h)
}

func TestUseCase_Handle_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	dto := usertokenban.Request{
		ID:           sharedtypes.NewRequestID(),
		SubjectID:    authshared.NewSubjectID(),
		TokenID:      int64(1234),
		Reason:       "reason ban test",
		CurrentToken: "current_token_any",
	}
	ts.authServiceMock.EXPECT().BanToken(ctx, dto.SubjectID, dto.TokenID, dto.Reason).Return(true, nil).Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	ts.Require().NoError(err)
	ts.True(res.Success)
}

func TestUseCase_Handle_Error(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	dto := usertokenban.Request{
		ID:           sharedtypes.NewRequestID(),
		SubjectID:    authshared.NewSubjectID(),
		TokenID:      int64(1234),
		Reason:       "reason ban test",
		CurrentToken: "current_token_any",
	}
	errExpect := errors.New("error expected")
	ts.authServiceMock.EXPECT().BanToken(ctx, dto.SubjectID, dto.TokenID, dto.Reason).
		Return(true, errExpect).Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	ts.Require().ErrorIs(err, errExpect)
	ts.False(res.Success)
}

func TestUseCase_Handle_Error_Validate(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	dto := usertokenban.Request{}

	res, err := ts.useCase.Handle(ctx, dto)
	ts.Require().Error(err)
	ts.False(res.Success)
}
