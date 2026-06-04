package usertokenlist_test

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

	"github.com/assurrussa/goauth/service/authjwtservice"
	authshared "github.com/assurrussa/goauth/shared"
	usertokenlist "github.com/assurrussa/goauth/usecases/query/user_token_list"
	usertokenlistmocks "github.com/assurrussa/goauth/usecases/query/user_token_list/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl     *gomock.Controller
	repoMock *usertokenlistmocks.MockauthService

	useCase *usertokenlist.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		repoMock := usertokenlistmocks.NewMockauthService(ctrl)

		return &TestUseCaseSuite{
			ctrl:     ctrl,
			repoMock: repoMock,
			useCase:  usertokenlist.Must(usertokenlist.NewOptions(logger.Discard(), repoMock)),
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		usertokenlist.Must(usertokenlist.NewOptions(nil, nil))
	})
}

func TestUseCase_Error(t *testing.T) {
	h, err := usertokenlist.New(usertokenlist.NewOptions(nil, nil))
	require.Error(t, err)
	assert.Empty(t, h)
}

func TestUseCase_Handle_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	subjectID := authshared.NewSubjectID()
	request := usertokenlist.Request{
		ID:           sharedtypes.NewRequestID(),
		SubjectID:    subjectID,
		CurrentToken: "any-token", //nolint:goconst // autofix
	}

	repoModels := []authjwtservice.TokenInfo{
		{ID: 101, Token: "any-token"},
		{ID: 102, Token: "any-token-2"},
	}

	ts.repoMock.EXPECT().GetUserTokens(ctx, subjectID, "any-token").Return(repoModels, nil).Times(1)

	response, err := ts.useCase.Handle(ctx, request)
	ts.Require().NoError(err)
	ts.Len(response.Tokens, 2)
	ts.Equal(int64(101), response.Tokens[0].ID)
	ts.Equal(int64(102), response.Tokens[1].ID)
}

func TestUseCase_Handle_Error(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	subjectID := authshared.NewSubjectID()
	request := usertokenlist.Request{
		ID:           sharedtypes.NewRequestID(),
		SubjectID:    subjectID,
		CurrentToken: "any-token",
	}
	errExpect := errors.New("error expected")

	ts.repoMock.EXPECT().GetUserTokens(ctx, subjectID, "any-token").Return(nil, errExpect).Times(1)

	response, err := ts.useCase.Handle(ctx, request)
	ts.Require().ErrorIs(err, errExpect)
	ts.Empty(response.Tokens)
}

func TestUseCase_Handle_Error_Validate(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	request := usertokenlist.Request{}

	response, err := ts.useCase.Handle(ctx, request)
	ts.Require().Error(err)
	ts.Empty(response.Tokens)
}
