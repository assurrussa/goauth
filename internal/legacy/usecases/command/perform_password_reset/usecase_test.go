package performpasswordreset_test

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/assurrussa/goauth/internal/legacy/local/passwordreset"
	performpasswordreset "github.com/assurrussa/goauth/internal/legacy/usecases/command/perform_password_reset"
	performpasswordresetmocks "github.com/assurrussa/goauth/internal/legacy/usecases/command/perform_password_reset/mocks"
)

func TestUseCase_Must(t *testing.T) {
	assert.Panics(t, func() {
		performpasswordreset.Must(performpasswordreset.NewOptions(nil, nil))
	})
}

func TestUseCase_Handle_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	service := performpasswordresetmocks.NewMockpasswordResetService(ctrl)
	uc := performpasswordreset.Must(performpasswordreset.NewOptions(logger.Discard(), service))
	ctx := context.Background()

	service.EXPECT().Perform(ctx, "user@test.com", "tok", "newpass").Return(nil).Times(1)

	resp, err := uc.Handle(ctx, performpasswordreset.Request{
		ID:              sharedtypes.NewRequestID(),
		Email:           "user@test.com", //nolint:goconst // autofix
		Token:           "tok",           //nolint:goconst // autofix
		Password:        "newpass",       //nolint:goconst // autofix
		ConfirmPassword: "newpass",
	})

	require.NoError(t, err)
	require.True(t, resp.Success)
}

func TestUseCase_Handle_InvalidRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	service := performpasswordresetmocks.NewMockpasswordResetService(ctrl)
	uc := performpasswordreset.Must(performpasswordreset.NewOptions(logger.Discard(), service))

	resp, err := uc.Handle(context.Background(), performpasswordreset.Request{})

	require.Error(t, err)
	require.ErrorIs(t, err, performpasswordreset.ErrInvalidRequest)
	require.False(t, resp.Success)
}

func TestUseCase_Handle_InvalidPasswordConfirm(t *testing.T) {
	ctrl := gomock.NewController(t)
	service := performpasswordresetmocks.NewMockpasswordResetService(ctrl)
	uc := performpasswordreset.Must(performpasswordreset.NewOptions(logger.Discard(), service))

	resp, err := uc.Handle(context.Background(), performpasswordreset.Request{
		ID:              sharedtypes.NewRequestID(),
		Email:           "user@test.com",
		Token:           "tok",
		Password:        "newpass",
		ConfirmPassword: "other",
	})

	require.Error(t, err)
	require.ErrorIs(t, err, performpasswordreset.ErrInvalidRequest)
	require.ErrorIs(t, err, performpasswordreset.ErrInvalidPasswordConfirm)
	require.False(t, resp.Success)
}

func TestUseCase_Handle_ServiceErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
	}{
		{
			name:   "invalid token",
			err:    passwordreset.ErrInvalidToken,
			target: performpasswordreset.ErrInvalidToken,
		},
		{
			name:   "same password",
			err:    passwordreset.ErrPasswordIsEqualCurrentPassword,
			target: performpasswordreset.ErrPasswordIsEqualCurrentPassword,
		},
		{
			name:   "other error",
			err:    errors.New("expected error"),
			target: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			service := performpasswordresetmocks.NewMockpasswordResetService(ctrl)
			uc := performpasswordreset.Must(performpasswordreset.NewOptions(logger.Discard(), service))
			ctx := context.Background()

			service.EXPECT().Perform(ctx, "user@test.com", "tok", "newpass").Return(tt.err).Times(1)

			resp, err := uc.Handle(ctx, performpasswordreset.Request{
				ID:              sharedtypes.NewRequestID(),
				Email:           "user@test.com",
				Token:           "tok",
				Password:        "newpass",
				ConfirmPassword: "newpass",
			})

			require.Error(t, err)
			if tt.target != nil {
				require.ErrorIs(t, err, tt.target)
			}
			require.ErrorIs(t, err, tt.err)
			require.False(t, resp.Success)
		})
	}
}
