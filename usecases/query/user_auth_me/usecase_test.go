package userauthme_test

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
	userauthme "github.com/assurrussa/goauth/usecases/query/user_auth_me"
	userauthmemocks "github.com/assurrussa/goauth/usecases/query/user_auth_me/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl              *gomock.Controller
	subjectLookupMock *userauthmemocks.MocksubjectLookup
	profileLookupMock *userauthmemocks.MockprofileLookup
	repoTokenMock     *userauthmemocks.MockrepoToken

	useCase *userauthme.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		subjectLookupMock := userauthmemocks.NewMocksubjectLookup(ctrl)
		profileLookupMock := userauthmemocks.NewMockprofileLookup(ctrl)
		repoTokenMock := userauthmemocks.NewMockrepoToken(ctrl)

		return &TestUseCaseSuite{
			ctrl:              ctrl,
			subjectLookupMock: subjectLookupMock,
			profileLookupMock: profileLookupMock,
			repoTokenMock:     repoTokenMock,
			useCase:           userauthme.Must(userauthme.NewOptions(logger.Discard(), subjectLookupMock, profileLookupMock, repoTokenMock)),
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		userauthme.Must(userauthme.NewOptions(nil, nil, nil, nil))
	})
}

func TestUseCase_Error(t *testing.T) {
	h, err := userauthme.New(userauthme.NewOptions(nil, nil, nil, nil))
	require.Error(t, err)
	assert.Empty(t, h)
}

func TestUseCase_Handle_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	request := userauthme.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: subjectID,
		Token:     "1234124",
		Version:   0,
	}

	expSubject := authcore.Subject{
		ID:              subjectID,
		Kind:            authcore.SubjectKindUser,
		PublicID:        userID,
		PasswordVersion: 0,
	}
	expProfile := authcore.Profile{
		ID:       123,
		PublicID: userID,
	}

	ts.subjectLookupMock.EXPECT().GetByID(ctx, subjectID).Return(expSubject, nil).Times(1)
	ts.profileLookupMock.EXPECT().GetBySubjectID(ctx, subjectID).Return(expProfile, nil).Times(1)

	response, err := ts.useCase.Handle(ctx, request)
	ts.Require().NoError(err)
	ts.Equal(expProfile, response.Profile)
}

func TestUseCase_Handle_Success_Version(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	request := userauthme.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: subjectID,
		Version:   123,
		Token:     "1234124",
	}

	expSubject := authcore.Subject{
		ID:              subjectID,
		Kind:            authcore.SubjectKindUser,
		PublicID:        userID,
		PasswordVersion: 123,
	}
	expProfile := authcore.Profile{ID: 123, PublicID: userID, PasswordChangedVersion: 123}

	ts.subjectLookupMock.EXPECT().GetByID(ctx, subjectID).Return(expSubject, nil).Times(1)
	ts.profileLookupMock.EXPECT().GetBySubjectID(ctx, subjectID).Return(expProfile, nil).Times(1)

	response, err := ts.useCase.Handle(ctx, request)
	ts.Require().NoError(err)
	ts.Equal(expProfile, response.Profile)
}

func TestUseCase_Handle_Error_Version(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	request := userauthme.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: subjectID,
		Version:   122,
		Token:     "1234124",
	}

	expSubject := authcore.Subject{
		ID:              subjectID,
		Kind:            authcore.SubjectKindUser,
		PublicID:        userID,
		PasswordVersion: 123,
	}

	ts.subjectLookupMock.EXPECT().GetByID(ctx, subjectID).Return(expSubject, nil).Times(1)
	ts.repoTokenMock.EXPECT().Delete(ctx, subjectID, request.Token).Return(true, nil).Times(1)

	response, err := ts.useCase.Handle(ctx, request)
	ts.Require().ErrorIs(err, userauthme.ErrInvalidPasswordVersion)
	ts.Empty(response.Profile)
}

func TestUseCase_Handle_Error_VersionDeleteRefreshToken(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	errExpect := errors.New("error expected")
	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	request := userauthme.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: subjectID,
		Version:   122,
		Token:     "1234124",
	}

	expSubject := authcore.Subject{
		ID:              subjectID,
		Kind:            authcore.SubjectKindUser,
		PublicID:        userID,
		PasswordVersion: 123,
	}

	ts.subjectLookupMock.EXPECT().GetByID(ctx, subjectID).Return(expSubject, nil).Times(1)
	ts.repoTokenMock.EXPECT().Delete(ctx, subjectID, request.Token).Return(true, errExpect).Times(1)

	response, err := ts.useCase.Handle(ctx, request)
	ts.Require().ErrorIs(err, userauthme.ErrInvalidPasswordVersion)
	ts.Require().ErrorIs(err, errExpect)
	ts.Empty(response.Profile)
}

func TestUseCase_Handle_Error(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	subjectID := authshared.NewSubjectID()
	request := userauthme.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: subjectID,
		Token:     "1234124",
	}
	errExpect := errors.New("error expected")

	ts.subjectLookupMock.EXPECT().GetByID(ctx, subjectID).Return(authcore.Subject{}, errExpect).Times(1)

	response, err := ts.useCase.Handle(ctx, request)
	ts.Require().ErrorIs(err, errExpect)
	ts.Empty(response.Profile)
}

func TestUseCase_Handle_Error_Validate(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)

	request := userauthme.Request{}

	response, err := ts.useCase.Handle(ctx, request)
	ts.Require().Error(err)
	ts.Empty(response.Profile)
}
