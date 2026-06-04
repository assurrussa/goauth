package cleanertokens_test

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	cleanertokens "github.com/assurrussa/goauth/usecases/command/cleaner_tokens"
	cleanertokensmocks "github.com/assurrussa/goauth/usecases/command/cleaner_tokens/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl           *gomock.Controller
	mockTransactor *cleanertokensmocks.Mocktransactor
	mockStorage    *cleanertokensmocks.Mockstorage

	useCase *cleanertokens.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		mockTransactor := cleanertokensmocks.NewMocktransactor(ctrl)
		mockStorage := cleanertokensmocks.NewMockstorage(ctrl)

		useCase := cleanertokens.Must(cleanertokens.NewOptions(
			logger.Discard(),
			mockStorage,
			mockTransactor,
		))

		return &TestUseCaseSuite{
			ctrl:           ctrl,
			mockTransactor: mockTransactor,
			mockStorage:    mockStorage,
			useCase:        useCase,
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		cleanertokens.Must(cleanertokens.NewOptions(nil, nil, nil))
	})
}

func TestUseCase_Handle_Success(t *testing.T) {
	// Arrange.
	ctx, _, ts := NewTestUseCaseSuite(t)

	ts.mockTransactor.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, f func(context.Context) error) error { return f(ctx) }).Times(2)

	req := cleanertokens.Request{
		BatchSize:  100,
		Iterations: 15,
		Minutes:    60,
	}
	ts.mockStorage.EXPECT().CleanupExpiredTokens(gomock.Any(), req.BatchSize, req.Minutes).
		Return(int64(25), nil).Times(1)
	ts.mockStorage.EXPECT().CleanupExpiredTokens(gomock.Any(), req.BatchSize, req.Minutes).
		Return(int64(0), nil).Times(1)

	// Action.
	resp, err := ts.useCase.Handle(ctx, req)

	// Assertion.
	ts.Require().NoError(err)
	ts.Equal(int64(25), resp.Total)
}

func TestUseCase_Handle_Error(t *testing.T) {
	// Arrange.
	ctx, _, ts := NewTestUseCaseSuite(t)

	ts.mockTransactor.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, f func(context.Context) error) error { return f(ctx) }).Times(1)

	errExpect := errors.New("test error")
	req := cleanertokens.Request{
		BatchSize:  100,
		Iterations: 15,
	}
	ts.mockStorage.EXPECT().CleanupExpiredTokens(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(int64(25), errExpect).Times(1)

	// Action.
	resp, err := ts.useCase.Handle(ctx, req)

	// Assertion.
	ts.Require().Error(err)
	ts.Require().ErrorIs(err, errExpect)
	ts.Empty(resp)
}

func TestUseCase_Handle_EmptyRequest(t *testing.T) {
	// Arrange.
	ctx, _, ts := NewTestUseCaseSuite(t)

	// Action.
	resp, err := ts.useCase.Handle(ctx, cleanertokens.Request{})

	// Assertion.
	ts.Require().Error(err)
	ts.Empty(resp)
}

func TestUseCase_MustInit(t *testing.T) {
	_, _, ts := NewTestUseCaseSuite(t)

	ts.Panics(func() {
		cleanertokens.Must(cleanertokens.NewOptions(nil, nil, nil))
	})
	ts.Panics(func() {
		cleanertokens.Must(cleanertokens.NewOptions(logger.Discard(), nil, nil))
	})
	ts.Panics(func() {
		cleanertokens.Must(cleanertokens.NewOptions(logger.Discard(), ts.mockStorage, nil))
	})

	// no panics
	ts.NotPanics(func() {
		cleanertokens.Must(cleanertokens.NewOptions(logger.Discard(), ts.mockStorage, ts.mockTransactor))
	})
}
