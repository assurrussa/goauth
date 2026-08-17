package adminsession

import (
	"context"

	"github.com/assurrussa/goshared/pkg/logger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	cleaneradminemailchanges "github.com/assurrussa/goauth/internal/legacy/usecases/command/cleaner_admin_email_changes"
)

type (
	CleanerAdminEmailChangesUseCase  = cleaneradminemailchanges.UseCase
	CleanerAdminEmailChangesRequest  = cleaneradminemailchanges.Request
	CleanerAdminEmailChangesResponse = cleaneradminemailchanges.Response
)

type EmailChangeCleanupStore interface {
	CleanupExpired(ctx context.Context, batchSize, minutes int) (int64, error)
}

func NewCleanerAdminEmailChangesUseCase(
	logger logger.Logger,
	store EmailChangeCleanupStore,
	tx authcore.TxManager,
) (*CleanerAdminEmailChangesUseCase, error) {
	return cleaneradminemailchanges.New(cleaneradminemailchanges.NewOptions(logger, store, tx))
}

func MustCleanerAdminEmailChangesUseCase(
	logger logger.Logger,
	store EmailChangeCleanupStore,
	tx authcore.TxManager,
) *CleanerAdminEmailChangesUseCase {
	return cleaneradminemailchanges.Must(cleaneradminemailchanges.NewOptions(logger, store, tx))
}
