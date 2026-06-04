package sendconfirmationcode_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	authcore "github.com/assurrussa/goauth/core"
	outboxtest "github.com/assurrussa/goauth/infrastructure/outbox/testsupport"
	shared2 "github.com/assurrussa/goauth/shared"
	sendconfirmationcode "github.com/assurrussa/goauth/usecases/command/send_confirmation_code"
	sendconfirmationcodemocks "github.com/assurrussa/goauth/usecases/command/send_confirmation_code/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl                     *gomock.Controller
	sendConfirmationCodeMock *sendconfirmationcodemocks.MockconfirmationService
	profilesMock             *sendconfirmationcodemocks.MockprofileLookup
	trxMock                  *outboxtest.MockTxManager

	useCase *sendconfirmationcode.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()

	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		sendConfirmationCodeMock := sendconfirmationcodemocks.NewMockconfirmationService(ctrl)
		profilesMock := sendconfirmationcodemocks.NewMockprofileLookup(ctrl)
		trxMock := outboxtest.NewMockTxManager(ctrl)

		useCase := sendconfirmationcode.Must(sendconfirmationcode.NewOptions(
			logger.Discard(),
			sendConfirmationCodeMock,
			profilesMock,
			trxMock,
		))

		return &TestUseCaseSuite{
			ctrl:                     ctrl,
			sendConfirmationCodeMock: sendConfirmationCodeMock,
			profilesMock:             profilesMock,
			trxMock:                  trxMock,
			useCase:                  useCase,
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		sendconfirmationcode.Must(sendconfirmationcode.NewOptions(nil, nil, nil, nil))
	})
}

func TestUseCase_Handle_Email_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	userID := sharedtypes.NewUserID()
	subjectID := shared2.NewSubjectID()

	req := sendconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: subjectID,
		CodeType:  shared2.ConfirmationTypeEmail,
	}

	profile := authcore.Profile{PublicID: userID, Email: "test@example.com", Name: "Test"}
	ts.profilesMock.EXPECT().GetBySubjectID(ctx, subjectID).Return(profile, nil)
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	ts.sendConfirmationCodeMock.EXPECT().
		GenerateAndSaveCode(
			ctx,
			subjectID,
			shared2.ConfirmationTypeEmail,
			shared2.ConfirmationPurposeConfirmation,
			"test@example.com",
		).Return(nil)

	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().NoError(err)
	ts.True(res.Success)
	ts.Equal("Код успешно отправлен.", res.Message)
}

func TestUseCase_Handle_Tg_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	userID := sharedtypes.NewUserID()
	subjectID := shared2.NewSubjectID()
	tgChatID := int64(123456789)

	req := sendconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: subjectID,
		CodeType:  shared2.ConfirmationTypeTgBot,
	}

	profile := authcore.Profile{PublicID: userID, Name: "Test", TelegramChatID: sql.NullInt64{Int64: tgChatID, Valid: true}}
	ts.profilesMock.EXPECT().GetBySubjectID(ctx, subjectID).Return(profile, nil)
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	ts.sendConfirmationCodeMock.EXPECT().
		GenerateAndSaveCode(
			ctx,
			subjectID,
			shared2.ConfirmationTypeTgBot,
			shared2.ConfirmationPurposeConfirmation,
			"123456789",
		).Return(nil)

	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().NoError(err)
	ts.True(res.Success)
}

func TestUseCase_Handle_Tg_NotLinked(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	userID := sharedtypes.NewUserID()
	subjectID := shared2.NewSubjectID()
	req := sendconfirmationcode.Request{ID: sharedtypes.NewRequestID(), SubjectID: subjectID, CodeType: shared2.ConfirmationTypeTgBot}

	ts.profilesMock.EXPECT().GetBySubjectID(ctx, subjectID).Return(authcore.Profile{PublicID: userID}, nil)

	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
}

func TestUseCase_Handle_Phone_NotSupportedForSend(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	subjectID := shared2.NewSubjectID()

	req := sendconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: subjectID,
		CodeType:  shared2.ConfirmationTypePhone,
	}

	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
}

func TestUseCase_Handle_InvalidRequest(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := sendconfirmationcode.Request{ // missing ID
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeEmail,
	}
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
}

func TestUseCase_Handle_UserRepoError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	subjectID := shared2.NewSubjectID()
	req := sendconfirmationcode.Request{ID: sharedtypes.NewRequestID(), SubjectID: subjectID, CodeType: shared2.ConfirmationTypeEmail}
	ts.profilesMock.EXPECT().GetBySubjectID(ctx, subjectID).Return(authcore.Profile{}, errors.New("boom"))
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
}

func TestUseCase_Handle_InvalidEmail(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	userID := sharedtypes.NewUserID()
	subjectID := shared2.NewSubjectID()
	req := sendconfirmationcode.Request{ID: sharedtypes.NewRequestID(), SubjectID: subjectID, CodeType: shared2.ConfirmationTypeEmail}
	ts.profilesMock.EXPECT().GetBySubjectID(ctx, subjectID).Return(authcore.Profile{PublicID: userID, Email: ""}, nil)
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
}

func TestUseCase_Handle_SendError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	userID := sharedtypes.NewUserID()
	subjectID := shared2.NewSubjectID()
	req := sendconfirmationcode.Request{ID: sharedtypes.NewRequestID(), SubjectID: subjectID, CodeType: shared2.ConfirmationTypeEmail}
	profile := authcore.Profile{PublicID: userID, Email: "test@example.com"}
	ts.profilesMock.EXPECT().GetBySubjectID(ctx, subjectID).Return(profile, nil)
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	ts.sendConfirmationCodeMock.EXPECT().
		GenerateAndSaveCode(
			ctx,
			subjectID,
			shared2.ConfirmationTypeEmail,
			shared2.ConfirmationPurposeConfirmation,
			"test@example.com",
		).Return(errors.New("svc"))
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
}
