package testsupport

import (
	"context"

	"github.com/jackc/pgx/v5"

	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
)

//go:generate mockgen -source=mocks.go -destination=mocks.gen.go -package=testsupport

type TxManager interface {
	RunInTx(ctx context.Context, f func(context.Context) error) error
	ReadCommitted(ctx context.Context, accessMode pgx.TxAccessMode, fn outbox.StoragePgsqlFnCallback) error
	RepeatableRead(ctx context.Context, accessMode pgx.TxAccessMode, fn outbox.StoragePgsqlFnCallback) error
	Serializable(ctx context.Context, accessMode pgx.TxAccessMode, fn outbox.StoragePgsqlFnCallback) error
}
