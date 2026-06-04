//nolint:testpackage // internal test
package confirmationrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/local/confirmation"
	"github.com/assurrussa/goauth/shared"
)

func TestRepoUpsertStatusAndList(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 18, 21, 10, 0, 0, time.UTC)
	record := confirmation.Record{
		SubjectID:        shared.MustParse[shared.SubjectID]("123e4567-e89b-12d3-a456-426614174101"),
		ConfirmationType: confirmation.TypeEmail,
		ConfirmationInfo: "user@example.com",
		Purpose:          confirmation.PurposeConfirmation,
		ConfirmedAt:      now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	repo := Must(&fakeClient{
		db: &fakeDB{
			getxFn: func(_ context.Context, op string, dest any, _ outbox.StoragePgsqlSqlizer) error {
				switch op {
				case "auth.confirmations.Upsert":
					id, ok := dest.(*int64)
					require.True(t, ok)
					*id = 7
					return nil
				default:
					t.Fatalf("unexpected getx operation %q", op)
					return nil
				}
			},
			selectxFn: func(_ context.Context, op string, dest any, _ outbox.StoragePgsqlSqlizer) error {
				require.Equal(t, "auth.confirmations.GetBySubjectID", op)
				rows, ok := dest.(*[]rowModel)
				require.True(t, ok)
				*rows = []rowModel{{
					ID:               7,
					SubjectID:        record.SubjectID,
					ConfirmationType: record.ConfirmationType.String(),
					ConfirmationInfo: record.ConfirmationInfo,
					Purpose:          record.Purpose.String(),
					ConfirmedAt:      record.ConfirmedAt,
					CreatedAt:        record.CreatedAt,
					UpdatedAt:        record.UpdatedAt,
				}}
				return nil
			},
			scanOnexFn: func(_ context.Context, op string, dest any, _ outbox.StoragePgsqlSqlizer) error {
				require.Equal(t, "auth.confirmations.IsConfirmed", op)
				flag, ok := dest.(*bool)
				require.True(t, ok)
				*flag = true
				return nil
			},
		},
	})

	id, err := repo.Upsert(ctx, record)
	require.NoError(t, err)
	require.Equal(t, int64(7), id)

	confirmed, err := repo.IsConfirmed(ctx, record.SubjectID, confirmation.TypeEmail, confirmation.PurposeConfirmation)
	require.NoError(t, err)
	require.True(t, confirmed)

	status, err := repo.GetConfirmationStatus(ctx, record.SubjectID)
	require.NoError(t, err)
	require.True(t, status.EmailConfirmed)

	records, err := repo.GetBySubjectID(ctx, record.SubjectID)
	require.NoError(t, err)
	require.Len(t, records, 1)
}

type fakeClient struct {
	db *fakeDB
}

func (c *fakeClient) DB() outbox.StoragePgsqlDBEngine { return c.db }
func (c *fakeClient) Close() error                    { return nil }

type fakeDB struct {
	getxFn     func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	selectxFn  func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	scanOnexFn func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
}

func (db *fakeDB) ScanOne(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanOne call")
}

func (db *fakeDB) ScanAll(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanAll call")
}

func (db *fakeDB) ScanOnex(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.scanOnexFn == nil {
		return nil
	}
	return db.scanOnexFn(ctx, op, dest, sqlizer)
}

func (db *fakeDB) ScanAllx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanAllx call")
}
func (db *fakeDB) QueryRow(context.Context, string, string, ...any) pgx.Row { return nil }
func (db *fakeDB) Query(context.Context, string, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query call")
}

func (db *fakeDB) Exec(context.Context, string, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), nil
}

func (db *fakeDB) Getx(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.getxFn == nil {
		return pgx.ErrNoRows
	}
	return db.getxFn(ctx, op, dest, sqlizer)
}

func (db *fakeDB) Selectx(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.selectxFn == nil {
		return nil
	}
	return db.selectxFn(ctx, op, dest, sqlizer)
}

func (db *fakeDB) Execx(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), nil
}

func (db *fakeDB) Queryx(context.Context, string, outbox.StoragePgsqlSqlizer) (pgx.Rows, error) {
	return nil, errors.New("unexpected Queryx call")
}
func (db *fakeDB) SendBatch(context.Context, string, *pgx.Batch) pgx.BatchResults { return nil }
func (db *fakeDB) CopyFrom(context.Context, string, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}

func (db *fakeDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not implemented")
}
func (db *fakeDB) Ping(context.Context) error { return nil }
func (db *fakeDB) Close()                     {}
func (db *fakeDB) Pool() *pgxpool.Pool        { return nil }

var _ outbox.StoragePgsqlDBEngine = (*fakeDB)(nil)
