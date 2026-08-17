package requestpasswordreset_test

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	requestpasswordreset "github.com/assurrussa/goauth/internal/legacy/usecases/command/request_password_reset"
	requestpasswordresetmocks "github.com/assurrussa/goauth/internal/legacy/usecases/command/request_password_reset/mocks"
)

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		requestpasswordreset.Must(requestpasswordreset.NewOptions(nil, nil))
	})
}

func TestUseCase_Handle_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	service := requestpasswordresetmocks.NewMockpasswordResetService(ctrl)
	uc := requestpasswordreset.Must(requestpasswordreset.NewOptions(logger.Discard(), service))
	ctx := context.Background()

	service.EXPECT().Request(ctx, "user@test.com").Return(nil).Times(1)

	resp, err := uc.Handle(ctx, requestpasswordreset.Request{
		ID:    sharedtypes.NewRequestID(),
		Email: "user@test.com",
	})

	require.NoError(t, err)
	require.True(t, resp.Success)
}

func TestUseCase_Handle_Error(t *testing.T) {
	ctrl := gomock.NewController(t)
	service := requestpasswordresetmocks.NewMockpasswordResetService(ctrl)
	uc := requestpasswordreset.Must(requestpasswordreset.NewOptions(logger.Discard(), service))
	ctx := context.Background()
	errExpected := errors.New("expected error")

	service.EXPECT().Request(ctx, "user@test.com").Return(errExpected).Times(1)

	resp, err := uc.Handle(ctx, requestpasswordreset.Request{
		ID:    sharedtypes.NewRequestID(),
		Email: "user@test.com",
	})

	require.Error(t, err)
	require.ErrorIs(t, err, errExpected)
	require.False(t, resp.Success)
}

func TestUseCase_Handle_InvalidRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	service := requestpasswordresetmocks.NewMockpasswordResetService(ctrl)
	uc := requestpasswordreset.Must(requestpasswordreset.NewOptions(logger.Discard(), service))

	resp, err := uc.Handle(context.Background(), requestpasswordreset.Request{})

	require.Error(t, err)
	require.False(t, resp.Success)
}
