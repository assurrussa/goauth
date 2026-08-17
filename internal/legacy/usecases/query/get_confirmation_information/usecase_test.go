package getconfirmationinformation_test

import (
	"context"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	authshared "github.com/assurrussa/goauth/internal/legacy/shared"
	getinfo "github.com/assurrussa/goauth/internal/legacy/usecases/query/get_confirmation_information"
	getinfomocks "github.com/assurrussa/goauth/internal/legacy/usecases/query/get_confirmation_information/mocks"
)

type Suite struct {
	suite.Suite
	ctrl    *gomock.Controller
	svc     *getinfomocks.MockconfirmationCodeService
	usecase *getinfo.UseCase
}

func NewSuite(t *testing.T) (context.Context, context.CancelFunc, *Suite) {
	t.Helper()
	return tests.NewSuite[*Suite](t, func(t *testing.T, _ context.Context) *Suite {
		t.Helper()
		ctrl := gomock.NewController(t)
		svc := getinfomocks.NewMockconfirmationCodeService(ctrl)
		uc := getinfo.Must(getinfo.NewOptions(logger.Discard(), svc))
		return &Suite{ctrl: ctrl, svc: svc, usecase: uc}
	})
}

func Test_Handle_Success(t *testing.T) {
	ctx, _, ts := NewSuite(t)
	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	q := getinfo.Query{SubjectID: subjectID}

	phone := int64(79991234567)
	info := authcore.ConfirmationInfo{
		Profile: authcore.Profile{PublicID: userID, Email: "test@example.com", Phone: &phone},
		Status: authcore.ConfirmationStatus{
			EmailConfirmed: true,
			PhoneConfirmed: false,
		},
	}

	ts.svc.EXPECT().GetConfirmationInfo(ctx, subjectID).Return(info, nil)

	res, err := ts.usecase.Handle(ctx, q)
	ts.Require().NoError(err)
	ts.Equal("test@example.com", res.Email)
	ts.Equal("79991234567", res.Phone)
	ts.True(res.IsEmailConfirmed)
	ts.False(res.IsPhoneConfirmed)
}

func Test_Handle_PhoneNil(t *testing.T) {
	ctx, _, ts := NewSuite(t)
	userID := sharedtypes.NewUserID()
	subjectID := authshared.NewSubjectID()
	q := getinfo.Query{SubjectID: subjectID}

	info := authcore.ConfirmationInfo{Profile: authcore.Profile{PublicID: userID, Email: "e@e"}}
	ts.svc.EXPECT().GetConfirmationInfo(ctx, subjectID).Return(info, nil)

	res, err := ts.usecase.Handle(ctx, q)
	ts.Require().NoError(err)
	ts.Equal("0", res.Phone) // Indirect(nil) -> 0
}

func Test_Must_Panics(t *testing.T) {
	// nil dependencies should cause Must to panic
	defer func() { _ = recover() }()
	_ = getinfo.Must(getinfo.NewOptions(nil, nil))
	t.Errorf("expected panic in Must with invalid options")
}

func Test_Handle_ServiceError(t *testing.T) {
	ctx, _, ts := NewSuite(t)
	subjectID := authshared.NewSubjectID()
	q := getinfo.Query{SubjectID: subjectID}
	ts.svc.EXPECT().GetConfirmationInfo(ctx, subjectID).Return(authcore.ConfirmationInfo{}, assert.AnError)
	_, err := ts.usecase.Handle(ctx, q)
	ts.Error(err)
}
