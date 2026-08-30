//nolint:testpackage // internal test
package refreshtokenrepo

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/core"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

func TestRepoSaveGetAndBan(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 18, 13, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174050")
	session := authcore.AuthSession{
		SubjectID:       subjectID,
		Kind:            authcore.SubjectKindUser,
		Token:           "refresh-1",
		PasswordVersion: 3,
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Hour),
	}
	var stored authcore.AuthSession

	db := &fakeRefreshDB{
		execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
			switch op {
			case "auth.refresh_tokens.Save":
				stored = session
			case "auth.refresh_tokens.Ban":
				reason := "manual"
				stored.Reason = &reason
				bannedAt := now.Add(time.Minute)
				stored.BannedAt = &bannedAt
			default:
				t.Fatalf("unexpected operation %q", op)
			}
			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
		getxFn: func(_ context.Context, op string, dest any, _ outbox.StoragePgsqlSqlizer) error {
			switch op {
			case "auth.refresh_tokens.Get":
				row, ok := dest.(*rowModel)
				require.True(t, ok)
				*row = rowModel{
					ID:              1,
					SubjectID:       stored.SubjectID,
					SubjectKind:     string(stored.Kind),
					Token:           stored.Token,
					PasswordVersion: stored.PasswordVersion,
					ExpiresAt:       stored.ExpiresAt,
					CreatedAt:       stored.CreatedAt,
					Reason:          nullableStringValue(stored.Reason),
					BannedAt:        nullableTimeValue(stored.BannedAt),
				}
				return nil
			default:
				t.Fatalf("unexpected operation %q", op)
				return nil
			}
		},
	}

	repo := Must(&fakeRefreshClient{db: db})
	require.NoError(t, repo.Save(ctx, session))

	got, err := repo.Get(ctx, session.Token)
	require.NoError(t, err)
	require.Equal(t, session.Token, got.Token)
	require.Nil(t, got.BannedAt)

	ok, err := repo.Ban(ctx, session.SubjectID, 1, "manual")
	require.NoError(t, err)
	require.True(t, ok)

	got, err = repo.Get(ctx, session.Token)
	require.NoError(t, err)
	require.NotNil(t, got.BannedAt)

	isBanned, err := repo.IsBanned(ctx, session.Token)
	require.NoError(t, err)
	require.True(t, isBanned)
}

type fakeRefreshClient struct {
	db *fakeRefreshDB
}

func (c *fakeRefreshClient) DB() outbox.StoragePgsqlDBEngine { return c.db }
func (c *fakeRefreshClient) Close() error                    { return nil }

type fakeRefreshDB struct {
	getxFn    func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	selectxFn func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	execxFn   func(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error)
}

func (db *fakeRefreshDB) ScanOne(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanOne call")
}

func (db *fakeRefreshDB) ScanAll(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanAll call")
}

func (db *fakeRefreshDB) ScanOnex(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanOnex call")
}

func (db *fakeRefreshDB) ScanAllx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanAllx call")
}
func (db *fakeRefreshDB) QueryRow(context.Context, string, string, ...any) pgx.Row { return nil }
func (db *fakeRefreshDB) Query(context.Context, string, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query call")
}

func (db *fakeRefreshDB) Exec(context.Context, string, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), nil
}

func (db *fakeRefreshDB) Getx(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.getxFn == nil {
		return pgx.ErrNoRows
	}
	return db.getxFn(ctx, op, dest, sqlizer)
}

func (db *fakeRefreshDB) Selectx(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.selectxFn == nil {
		return nil
	}
	return db.selectxFn(ctx, op, dest, sqlizer)
}

func (db *fakeRefreshDB) Execx(ctx context.Context, op string, sqlizer outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
	if db.execxFn == nil {
		return pgconn.NewCommandTag(""), nil
	}
	return db.execxFn(ctx, op, sqlizer)
}

func (db *fakeRefreshDB) Queryx(context.Context, string, outbox.StoragePgsqlSqlizer) (pgx.Rows, error) {
	return nil, errors.New("unexpected Queryx call")
}

func (db *fakeRefreshDB) SendBatch(context.Context, string, *pgx.Batch) pgx.BatchResults { return nil }

func (db *fakeRefreshDB) CopyFrom(context.Context, string, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}

func (db *fakeRefreshDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not implemented")
}
func (db *fakeRefreshDB) Ping(context.Context) error { return nil }
func (db *fakeRefreshDB) Close()                     {}
func (db *fakeRefreshDB) Pool() *pgxpool.Pool        { return nil }

func nullableStringValue(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *value, Valid: true}
}

func nullableTimeValue(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}

var _ outbox.StoragePgsqlDBEngine = (*fakeRefreshDB)(nil)
