package localjwt

import (
	"context"

	"github.com/assurrussa/goshared/pkg/logger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	cleanerconfirmationcode "github.com/assurrussa/goauth/internal/legacy/usecases/command/cleaner_confirmation_code"
	cleanerpasswordresettokens "github.com/assurrussa/goauth/internal/legacy/usecases/command/cleaner_password_reset_tokens"
	cleanertokens "github.com/assurrussa/goauth/internal/legacy/usecases/command/cleaner_tokens"
)

type TokenCleanupStore interface {
	CleanupExpiredTokens(ctx context.Context, batchSize, minutes int) (int64, error)
}

type PasswordResetTokenCleanupStore interface {
	CleanupExpiredPasswordTokens(ctx context.Context, batchSize, minutes int) (int64, error)
}

type ConfirmationCodeCleanupStore interface {
	CleanupExpiredCodes(ctx context.Context, batchSize, minutes int) (int64, error)
}

func NewCleanerTokensUseCase(
	logger logger.Logger,
	store TokenCleanupStore,
	tx authcore.TxManager,
) (*CleanerTokensUseCase, error) {
	return cleanertokens.New(cleanertokens.NewOptions(logger, store, tx))
}

func MustCleanerTokensUseCase(
	logger logger.Logger,
	store TokenCleanupStore,
	tx authcore.TxManager,
) *CleanerTokensUseCase {
	return cleanertokens.Must(cleanertokens.NewOptions(logger, store, tx))
}

func NewCleanerPasswordResetsUseCase(
	logger logger.Logger,
	store PasswordResetTokenCleanupStore,
	tx authcore.TxManager,
) (*CleanerPasswordResetsUseCase, error) {
	return cleanerpasswordresettokens.New(cleanerpasswordresettokens.NewOptions(logger, store, tx))
}

func MustCleanerPasswordResetsUseCase(
	logger logger.Logger,
	store PasswordResetTokenCleanupStore,
	tx authcore.TxManager,
) *CleanerPasswordResetsUseCase {
	return cleanerpasswordresettokens.Must(cleanerpasswordresettokens.NewOptions(logger, store, tx))
}

func NewCleanerConfirmationCodesUseCase(
	logger logger.Logger,
	store ConfirmationCodeCleanupStore,
	tx authcore.TxManager,
) (*CleanerConfirmationCodesUseCase, error) {
	return cleanerconfirmationcode.New(cleanerconfirmationcode.NewOptions(logger, store, tx))
}

func MustCleanerConfirmationCodesUseCase(
	logger logger.Logger,
	store ConfirmationCodeCleanupStore,
	tx authcore.TxManager,
) *CleanerConfirmationCodesUseCase {
	return cleanerconfirmationcode.Must(cleanerconfirmationcode.NewOptions(logger, store, tx))
}
