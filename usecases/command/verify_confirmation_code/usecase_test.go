package verifyconfirmationcode_test

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	outboxtest "github.com/assurrussa/goauth/infrastructure/outbox/testsupport"
	"github.com/assurrussa/goauth/service/confirmationcodeservice"
	shared2 "github.com/assurrussa/goauth/shared"
	verifyconfirmationcode "github.com/assurrussa/goauth/usecases/command/verify_confirmation_code"
	verifyconfirmationcodemocks "github.com/assurrussa/goauth/usecases/command/verify_confirmation_code/mocks"
)

type TestUseCaseSuite struct {
	suite.Suite

	ctrl    *gomock.Controller
	svcMock *verifyconfirmationcodemocks.MockconfirmationService
	trxMock *outboxtest.MockTxManager
	useCase *verifyconfirmationcode.UseCase
}

func NewTestUseCaseSuite(t *testing.T) (context.Context, context.CancelFunc, *TestUseCaseSuite) {
	t.Helper()
	return tests.NewSuite[*TestUseCaseSuite](t, func(t *testing.T, _ context.Context) *TestUseCaseSuite {
		t.Helper()
		ctrl := gomock.NewController(t)
		svc := verifyconfirmationcodemocks.NewMockconfirmationService(ctrl)
		trxMock := outboxtest.NewMockTxManager(ctrl)
		uc := verifyconfirmationcode.Must(verifyconfirmationcode.NewOptions(
			logger.Discard(),
			svc,
			trxMock,
		))
		return &TestUseCaseSuite{
			ctrl:    ctrl,
			svcMock: svc,
			trxMock: trxMock,
			useCase: uc,
		}
	})
}

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		verifyconfirmationcode.Must(verifyconfirmationcode.NewOptions(nil, nil, nil))
	})
}

func TestUseCase_Handle_Success(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	subjectID := shared2.NewSubjectID()
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: subjectID,
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      "123456",
	}
	ts.svcMock.EXPECT().VerifyCode(
		ctx,
		req.SubjectID,
		shared2.ConfirmCode("123456"),
		shared2.ConfirmationTypeEmail,
		shared2.ConfirmationPurposeConfirmation,
	).Return(nil)
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().NoError(err)
	ts.True(res.Success)
	ts.True(res.Confirmed)
}

func TestUseCase_Handle_ValidationError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      "",
	}
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
	ts.False(res.Confirmed)
}

func TestUseCase_Handle_ServiceError(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      "123456",
	}
	ts.svcMock.EXPECT().VerifyCode(
		ctx,
		req.SubjectID,
		shared2.ConfirmCode("123456"),
		shared2.ConfirmationTypeEmail,
		shared2.ConfirmationPurposeConfirmation,
	).Return(confirmationcodeservice.ErrInvalidCode)
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().NoError(err)
	ts.False(res.Success)
	ts.False(res.Confirmed)
	ts.Empty(res.Message)
	ts.Equal("invalid_code", res.Reason)
}

func TestUseCase_Handle_NormalizesCode(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      " １２３- 4\t5\n6 ",
	}
	// Current workflow normalization strips whitespace and preserves the raw code payload.
	ts.svcMock.EXPECT().VerifyCode(
		ctx,
		req.SubjectID,
		shared2.ConfirmCode("１２３-456"),
		shared2.ConfirmationTypeEmail,
		shared2.ConfirmationPurposeConfirmation,
	).Return(nil)
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().NoError(err)
	ts.True(res.Success)
	ts.True(res.Confirmed)
}

func TestUseCase_Handle_InvalidCodeType(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeUnknown,
		Code:      "123456",
	}
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
	ts.False(res.Confirmed)
}

func TestUseCase_Handle_ReasonExpired(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      "123456",
	}
	ts.svcMock.EXPECT().VerifyCode(
		ctx,
		req.SubjectID,
		shared2.ConfirmCode("123456"),
		shared2.ConfirmationTypeEmail,
		shared2.ConfirmationPurposeConfirmation,
	).Return(confirmationcodeservice.ErrCodeExpired)
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().NoError(err)
	ts.False(res.Success)
	ts.Equal("expired", res.Reason)
}

func TestUseCase_Handle_ReasonAlreadyVerified(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      "123456",
	}
	ts.svcMock.EXPECT().VerifyCode(
		ctx,
		req.SubjectID,
		shared2.ConfirmCode("123456"),
		shared2.ConfirmationTypeEmail,
		shared2.ConfirmationPurposeConfirmation,
	).Return(confirmationcodeservice.ErrAlreadyVerified)
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().NoError(err)
	ts.False(res.Success)
	ts.Equal("already_verified", res.Reason)
}

func TestUseCase_Handle_ReasonMaxAttempts(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      "123456",
	}
	ts.svcMock.EXPECT().VerifyCode(
		ctx,
		req.SubjectID,
		shared2.ConfirmCode("123456"),
		shared2.ConfirmationTypeEmail,
		shared2.ConfirmationPurposeConfirmation,
	).Return(confirmationcodeservice.ErrMaxAttempts)
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().NoError(err)
	ts.False(res.Success)
	ts.Equal("max_attempts", res.Reason)
}

func TestUseCase_Handle_ReasonUnknown(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      "123456",
	}
	ts.svcMock.EXPECT().VerifyCode(
		ctx,
		req.SubjectID,
		shared2.ConfirmCode("123456"),
		shared2.ConfirmationTypeEmail,
		shared2.ConfirmationPurposeConfirmation,
	).Return(errors.New("some other error"))
	ts.trxMock.EXPECT().RunInTx(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, fn func(ctx context.Context) error) error {
			return fn(ctx)
		}).Times(1)
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
}

func TestUseCase_Handle_MissingRequestID(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{ // missing ID
		SubjectID: shared2.NewSubjectID(),
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      "123456",
	}
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
}

func TestUseCase_Handle_MissingSubjectID(t *testing.T) {
	ctx, _, ts := NewTestUseCaseSuite(t)
	req := verifyconfirmationcode.Request{
		ID:        sharedtypes.NewRequestID(),
		SubjectID: shared2.SubjectIDNil,
		CodeType:  shared2.ConfirmationTypeEmail,
		Code:      "123456",
	}
	res, err := ts.useCase.Handle(ctx, req)
	ts.Require().Error(err)
	ts.False(res.Success)
}
