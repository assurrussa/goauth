package oidc

import (
	"context"

	logger "github.com/assurrussa/gologger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	cleaneroidcrefreshtokens "github.com/assurrussa/goauth/internal/legacy/usecases/command/cleaner_oidc_refresh_tokens"
)

type (
	RefreshTokenCleanerUseCase  = cleaneroidcrefreshtokens.UseCase
	RefreshTokenCleanerRequest  = cleaneroidcrefreshtokens.Request
	RefreshTokenCleanerResponse = cleaneroidcrefreshtokens.Response
)

type RefreshTokenCleanupStore interface {
	CleanupExpiredTokens(ctx context.Context, batchSize, minutes int) (int64, error)
}

func NewRefreshTokenCleanerUseCase(
	logger logger.Logger,
	store RefreshTokenCleanupStore,
	tx authcore.TxManager,
) (*RefreshTokenCleanerUseCase, error) {
	return cleaneroidcrefreshtokens.New(cleaneroidcrefreshtokens.NewOptions(logger, store, tx))
}

func MustRefreshTokenCleanerUseCase(
	logger logger.Logger,
	store RefreshTokenCleanupStore,
	tx authcore.TxManager,
) *RefreshTokenCleanerUseCase {
	return cleaneroidcrefreshtokens.Must(cleaneroidcrefreshtokens.NewOptions(logger, store, tx))
}
