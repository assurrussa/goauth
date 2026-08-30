//nolint:testpackage // internal test
package sessionrepo

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

func TestRepoSaveGetAndDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 18, 14, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174060")
	session := authcore.AuthSession{
		SubjectID:       subjectID,
		Kind:            authcore.SubjectKindAdmin,
		Token:           "session-1",
		PasswordVersion: 2,
		CreatedAt:       now,
		ExpiresAt:       now.Add(2 * time.Hour),
	}
	payload := []byte(`{"id":42,"email":"admin@example.com"}`)

	var storedSession authcore.AuthSession
	var storedPayload []byte

	db := &fakeSessionDB{
		execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
			switch op {
			case "auth.sessions.Save":
				storedSession = session
				storedPayload = append([]byte(nil), payload...)
			case "auth.sessions.Delete":
			default:
				t.Fatalf("unexpected operation %q", op)
			}

			return pgconn.NewCommandTag("DELETE 1"), nil
		},
		getxFn: func(_ context.Context, op string, dest any, _ outbox.StoragePgsqlSqlizer) error {
			switch op {
			case "auth.sessions.Get":
				row, ok := dest.(*rowModel)
				require.True(t, ok)
				*row = rowModel{
					ID:              1,
					SubjectID:       storedSession.SubjectID,
					SubjectKind:     string(storedSession.Kind),
					Token:           storedSession.Token,
					Payload:         append([]byte(nil), storedPayload...),
					PasswordVersion: storedSession.PasswordVersion,
					CreatedAt:       storedSession.CreatedAt,
					ExpiresAt:       storedSession.ExpiresAt,
					RevokedAt:       nullableTimeValue(storedSession.RevokedAt),
				}
				return nil
			default:
				t.Fatalf("unexpected operation %q", op)
				return nil
			}
		},
	}

	repo := Must(&fakeSessionClient{db: db})
	require.NoError(t, repo.Save(ctx, session, payload))

	gotSession, gotPayload, err := repo.Get(ctx, session.Token)
	require.NoError(t, err)
	require.Equal(t, session.Token, gotSession.Token)
	require.Equal(t, payload, gotPayload)

	require.NoError(t, repo.Delete(ctx, session.Token))
}

func TestRepoDeleteAll(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var gotOp string
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174061")

	db := &fakeSessionDB{
		execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
			gotOp = op
			return pgconn.NewCommandTag("DELETE 3"), nil
		},
	}

	repo := Must(&fakeSessionClient{db: db})
	count, err := repo.DeleteAll(ctx, subjectID)
	require.NoError(t, err)
	require.Equal(t, "auth.sessions.DeleteAll", gotOp)
	require.EqualValues(t, 3, count)
}

func TestRepoDeleteAllExcept(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	var gotOp string
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174062")

	db := &fakeSessionDB{
		execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
			gotOp = op
			return pgconn.NewCommandTag("DELETE 2"), nil
		},
	}

	repo := Must(&fakeSessionClient{db: db})
	count, err := repo.DeleteAllExcept(ctx, subjectID, "session-keep")
	require.NoError(t, err)
	require.Equal(t, "auth.sessions.DeleteAllExcept", gotOp)
	require.EqualValues(t, 2, count)
}

type fakeSessionClient struct {
	db *fakeSessionDB
}

func (c *fakeSessionClient) DB() outbox.StoragePgsqlDBEngine { return c.db }
func (c *fakeSessionClient) Close() error                    { return nil }

type fakeSessionDB struct {
	getxFn  func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	execxFn func(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error)
}

func (db *fakeSessionDB) ScanOne(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanOne call")
}

func (db *fakeSessionDB) ScanAll(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanAll call")
}

func (db *fakeSessionDB) ScanOnex(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanOnex call")
}

func (db *fakeSessionDB) ScanAllx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanAllx call")
}
func (db *fakeSessionDB) QueryRow(context.Context, string, string, ...any) pgx.Row { return nil }
func (db *fakeSessionDB) Query(context.Context, string, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query call")
}

func (db *fakeSessionDB) Exec(context.Context, string, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), nil
}

func (db *fakeSessionDB) Getx(ctx context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
	if db.getxFn == nil {
		return pgx.ErrNoRows
	}
	return db.getxFn(ctx, op, dest, sqlizer)
}

func (db *fakeSessionDB) Selectx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected Selectx call")
}

func (db *fakeSessionDB) Execx(ctx context.Context, op string, sqlizer outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
	if db.execxFn == nil {
		return pgconn.NewCommandTag(""), nil
	}
	return db.execxFn(ctx, op, sqlizer)
}

func (db *fakeSessionDB) Queryx(context.Context, string, outbox.StoragePgsqlSqlizer) (pgx.Rows, error) {
	return nil, errors.New("unexpected Queryx call")
}

func (db *fakeSessionDB) SendBatch(context.Context, string, *pgx.Batch) pgx.BatchResults { return nil }

func (db *fakeSessionDB) CopyFrom(context.Context, string, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}

func (db *fakeSessionDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("not implemented")
}
func (db *fakeSessionDB) Ping(context.Context) error { return nil }
func (db *fakeSessionDB) Close()                     {}
func (db *fakeSessionDB) Pool() *pgxpool.Pool        { return nil }

func nullableTimeValue(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}

var _ outbox.StoragePgsqlDBEngine = (*fakeSessionDB)(nil)
