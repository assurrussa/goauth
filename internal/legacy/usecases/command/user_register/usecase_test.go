package userregister_test

import (
	"context"
	"errors"
	"testing"

	logger "github.com/assurrussa/gologger"
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	authshared "github.com/assurrussa/goauth/internal/legacy/shared"
	userregister "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_register"
	userregistermocks "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_register/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl            *gomock.Controller
	authServiceMock *userregistermocks.MockauthService

	useCase *userregister.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		authServiceMock := userregistermocks.NewMockauthService(ctrl)

		return &TestUseCaseSuite{
			ctrl:            ctrl,
			authServiceMock: authServiceMock,
			useCase:         userregister.Must(userregister.NewOptions(logger.Discard(), authServiceMock)),
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		userregister.Must(userregister.NewOptions(nil, nil))
	})
}

func TestUseCase_Error(t *testing.T) {
	h, err := userregister.New(userregister.NewOptions(nil, nil))
	require.Error(t, err)
	assert.Empty(t, h)
}

func TestUseCase_Execute_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	expectUserID := sharedtypes.NewUserID()
	expectSubject := authcore.Subject{
		ID:       authshared.NewSubjectID(),
		Kind:     authcore.SubjectKindUser,
		PublicID: expectUserID,
	}
	dto := userregister.Request{
		ID:                sharedtypes.NewRequestID(),
		Email:             "test@test.com",
		Name:              "Amir",
		Password:          "password", //nolint:goconst // autofix
		ConfirmedPassword: "password",
	}
	ts.authServiceMock.EXPECT().Register(ctx, dto.Email, dto.Password, dto.ConfirmedPassword, dto.Name).
		Return(expectSubject, nil).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	require.NoError(t, err)
	assert.Equal(t, expectSubject.ID, res.SubjectID)
}

func TestUseCase_Execute_AuthServiceError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	errExpected := errors.New("expected error")
	dto := userregister.Request{
		ID:                sharedtypes.NewRequestID(),
		Email:             "test@test.com",
		Name:              "Amir",
		Password:          "password",
		ConfirmedPassword: "password",
	}
	ts.authServiceMock.EXPECT().Register(ctx, dto.Email, dto.Password, dto.ConfirmedPassword, dto.Name).
		Return(authcore.Subject{}, errExpected).
		Times(1)

	res, err := ts.useCase.Handle(ctx, dto)
	require.Error(t, err)
	require.ErrorIs(t, err, errExpected)
	assert.Empty(t, res)
}

func TestUseCase_Execute_ValidateError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	dto := userregister.Request{}

	res, err := ts.useCase.Handle(ctx, dto)
	require.Error(t, err)
	assert.Empty(t, res)
}
