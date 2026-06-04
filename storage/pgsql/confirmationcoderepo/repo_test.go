package confirmationcoderepo

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

func TestRepoUpsertGetAndCount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 18, 21, 0, 0, 0, time.UTC)
	record := confirmation.CodeRecord{
		SubjectID:        shared.MustParse[shared.SubjectID]("123e4567-e89b-12d3-a456-426614174102"),
		Code:             confirmation.Code("123456"),
		ConfirmationType: confirmation.TypeEmail,
		ConfirmationInfo: "user@example.com",
		Purpose:          confirmation.PurposeConfirmation,
		ExpiresAt:        now.Add(time.Hour),
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	repo := Must(&fakeClient{
		db: &fakeDB{
			getxFn: func(_ context.Context, op string, dest any, _ outbox.StoragePgsqlSqlizer) error {
				switch op {
				case "auth.confirmation_codes.UpsertCode":
					id, ok := dest.(*int64)
					require.True(t, ok)
					*id = 11
					return nil
				case "auth.confirmation_codes.GetActiveCodeBySubjectAndType":
					row, ok := dest.(*rowModel)
					require.True(t, ok)
					*row = rowModel{
						ID:               11,
						SubjectID:        record.SubjectID,
						Code:             record.Code.String(),
						ConfirmationType: record.ConfirmationType.String(),
						ConfirmationInfo: record.ConfirmationInfo,
						Purpose:          record.Purpose.String(),
						ExpiresAt:        record.ExpiresAt,
						CreatedAt:        record.CreatedAt,
						UpdatedAt:        record.UpdatedAt,
					}
					return nil
				default:
					t.Fatalf("unexpected operation %q", op)
					return nil
				}
			},
			scanOnexFn: func(_ context.Context, op string, dest any, _ outbox.StoragePgsqlSqlizer) error {
				require.Equal(t, "auth.confirmation_codes.CountSince", op)
				window, ok := dest.(*usageWindowModel)
				require.True(t, ok)
				*window = usageWindowModel{LastHour: 1, Last24h: 2}
				return nil
			},
			execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
				switch op {
				case "auth.confirmation_codes.UpdateVerified", "auth.confirmation_codes.IncrementAttempts":
					return pgconn.NewCommandTag("UPDATE 1"), nil
				default:
					t.Fatalf("unexpected exec operation %q", op)
					return pgconn.NewCommandTag(""), nil
				}
			},
		},
	})

	id, err := repo.UpsertCode(ctx, record)
	require.NoError(t, err)
	require.Equal(t, int64(11), id)

	got, err := repo.GetActiveCodeBySubjectAndType(ctx, record.SubjectID, confirmation.TypeEmail, confirmation.PurposeConfirmation)
	require.NoError(t, err)
	require.Equal(t, confirmation.Code("123456"), got.Code)

	window, err := repo.CountSince(ctx, record.SubjectID, confirmation.TypeEmail, now)
	require.NoError(t, err)
	require.Equal(t, 1, window.LastHour)
	require.Equal(t, 2, window.Last24h)
}

type fakeClient struct {
	db *fakeDB
}

func (c *fakeClient) DB() outbox.StoragePgsqlDBEngine { return c.db }
func (c *fakeClient) Close() error                    { return nil }

type fakeDB struct {
	getxFn     func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	scanOnexFn func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	execxFn    func(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error)
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
	return pgconn.NewCommandTag("DELETE 1"), nil
}

func (db *fakeDB) Getx(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.getxFn == nil {
		return pgx.ErrNoRows
	}
	return db.getxFn(ctx, op, dest, sqlizer)
}
func (db *fakeDB) Selectx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error { return nil }
func (db *fakeDB) Execx(ctx context.Context, op string, sqlizer outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
	if db.execxFn == nil {
		return pgconn.NewCommandTag(""), nil
	}
	return db.execxFn(ctx, op, sqlizer)
}

func (db *fakeDB) Queryx(context.Context, string, outbox.StoragePgsqlSqlizer) (pgx.Rows, error) {
	return nil, errors.New("unexpected Queryx call")
}
func (db *fakeDB) SendBatch(context.Context, string, *pgx.Batch) pgx.BatchResults { return nil }
func (db *fakeDB) CopyFrom(context.Context, string, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}
func (db *fakeDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) { return nil, nil }
func (db *fakeDB) Ping(context.Context) error                             { return nil }
func (db *fakeDB) Close()                                                 {}
func (db *fakeDB) Pool() *pgxpool.Pool                                    { return nil }

var _ outbox.StoragePgsqlDBEngine = (*fakeDB)(nil)
