//nolint:testpackage // internal test
package oidcrefreshtokenrepo

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

	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
	"github.com/assurrussa/goauth/oidc"
)

func TestRepoSaveAndGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	token := oidc.RefreshToken{
		//nolint:goconst // test
		Token: "refresh-1",
		//nolint:goconst // test
		SubjectID: "123e4567-e89b-12d3-a456-426614174100",
		//nolint:goconst // test
		ClientID:        "pet-app",
		Scopes:          []string{oidc.ScopeEmail, oidc.ScopeOpenID},
		SecurityVersion: 7,
		AuthenticatedAt: time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC),
		CreatedAt:       time.Date(2026, 4, 18, 12, 1, 0, 0, time.UTC),
		ExpiresAt:       time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC),
	}

	stored := map[string]oidc.RefreshToken{}
	saveQueue := []oidc.RefreshToken{token}
	db := &fakeRefreshTokenDB{
		execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
			require.Equal(t, "oidc.refresh_tokens.Save", op)
			require.NotEmpty(t, saveQueue)

			next := saveQueue[0]
			saveQueue = saveQueue[1:]
			stored[next.Token] = next

			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
		getxFn: func(_ context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
			require.Equal(t, "oidc.refresh_tokens.Get", op)

			_, args, err := sqlizer.ToSql()
			require.NoError(t, err)
			require.Len(t, args, 1)

			tokenID, _ := args[0].(string)
			record, ok := stored[tokenID]
			if !ok {
				return pgx.ErrNoRows
			}

			row, ok := dest.(*refreshTokenRow)
			require.True(t, ok)
			*row = refreshTokenRowFromDomain(record)
			return nil
		},
	}

	repo, err := New(NewOptions(&fakeRefreshTokenClient{db: db}, &fakeRefreshTokenTxManager{}))
	require.NoError(t, err)

	require.NoError(t, repo.Save(ctx, token))

	got, err := repo.Get(ctx, token.Token)
	require.NoError(t, err)
	require.Equal(t, token.Token, got.Token)
	require.Equal(t, token.SubjectID, got.SubjectID)
	require.Equal(t, oidc.ScopeString(token.Scopes), oidc.ScopeString(got.Scopes))
	require.Nil(t, got.RevokedAt)
}

func TestRepoRevokeMarksTokenRevoked(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 18, 13, 0, 0, 0, time.UTC)
	stored := map[string]oidc.RefreshToken{
		"refresh-1": {
			Token: "refresh-1",

			SubjectID: "123e4567-e89b-12d3-a456-426614174100",

			ClientID:        "pet-app",
			Scopes:          []string{oidc.ScopeOpenID},
			SecurityVersion: 3,
			AuthenticatedAt: now.Add(-time.Hour),
			CreatedAt:       now.Add(-time.Hour),
			ExpiresAt:       now.Add(time.Hour),
		},
	}

	currentToken := "refresh-1"
	currentRevokedAt := now
	db := &fakeRefreshTokenDB{
		execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
			require.Equal(t, "oidc.refresh_tokens.Revoke", op)

			record := stored[currentToken]
			record.RevokedAt = &currentRevokedAt
			stored[currentToken] = record

			return pgconn.NewCommandTag("UPDATE 1"), nil
		},
		getxFn: func(_ context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
			require.Equal(t, "oidc.refresh_tokens.Get", op)

			_, args, err := sqlizer.ToSql()
			require.NoError(t, err)
			tokenID, _ := args[0].(string)
			record := stored[tokenID]

			row, ok := dest.(*refreshTokenRow)
			require.True(t, ok)
			*row = refreshTokenRowFromDomain(record)
			return nil
		},
	}

	repo, err := New(NewOptions(&fakeRefreshTokenClient{db: db}, &fakeRefreshTokenTxManager{}))
	require.NoError(t, err)

	require.NoError(t, repo.Revoke(ctx, currentToken, currentRevokedAt))

	got, err := repo.Get(ctx, currentToken)
	require.NoError(t, err)
	require.NotNil(t, got.RevokedAt)
	require.Equal(t, currentRevokedAt, *got.RevokedAt)
}

func TestRepoRotateRevokesCurrentAndStoresNext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 18, 14, 0, 0, 0, time.UTC)
	current := oidc.RefreshToken{
		Token: "refresh-1",

		SubjectID: "123e4567-e89b-12d3-a456-426614174100",

		ClientID:        "pet-app",
		Scopes:          []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID},
		SecurityVersion: 4,
		AuthenticatedAt: now.Add(-time.Hour),
		CreatedAt:       now.Add(-time.Hour),
		ExpiresAt:       now.Add(time.Hour),
	}
	next := oidc.RefreshToken{
		Token:           "refresh-2",
		SubjectID:       current.SubjectID,
		ClientID:        current.ClientID,
		Scopes:          current.Scopes,
		SecurityVersion: current.SecurityVersion,
		AuthenticatedAt: current.AuthenticatedAt,
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
	}

	stored := map[string]oidc.RefreshToken{current.Token: current}
	saveQueue := []oidc.RefreshToken{next}
	rotateToken := current.Token
	rotateAt := now
	txRuns := 0
	db := &fakeRefreshTokenDB{
		execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
			switch op {
			case "oidc.refresh_tokens.Rotate.revoke":
				record, ok := stored[rotateToken]
				if !ok || record.RevokedAt != nil {
					return pgconn.NewCommandTag("UPDATE 0"), nil
				}

				record.RevokedAt = &rotateAt
				stored[rotateToken] = record
				return pgconn.NewCommandTag("UPDATE 1"), nil
			case "oidc.refresh_tokens.Save":
				require.NotEmpty(t, saveQueue)
				token := saveQueue[0]
				saveQueue = saveQueue[1:]
				stored[token.Token] = token
				return pgconn.NewCommandTag("INSERT 0 1"), nil
			default:
				t.Fatalf("unexpected operation %q", op)
				return pgconn.NewCommandTag(""), nil
			}
		},
		getxFn: func(_ context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
			require.Equal(t, "oidc.refresh_tokens.Get", op)

			_, args, err := sqlizer.ToSql()
			require.NoError(t, err)
			tokenID, _ := args[0].(string)
			record, ok := stored[tokenID]
			if !ok {
				return pgx.ErrNoRows
			}

			row, ok := dest.(*refreshTokenRow)
			require.True(t, ok)
			*row = refreshTokenRowFromDomain(record)
			return nil
		},
	}
	txManager := &fakeRefreshTokenTxManager{
		runInTxFn: func(ctx context.Context, fn func(context.Context) error) error {
			txRuns++
			return fn(ctx)
		},
	}

	repo, err := New(NewOptions(&fakeRefreshTokenClient{db: db}, txManager))
	require.NoError(t, err)

	require.NoError(t, repo.Rotate(ctx, current.Token, next, rotateAt))
	require.Equal(t, 1, txRuns)

	gotCurrent, err := repo.Get(ctx, current.Token)
	require.NoError(t, err)
	require.NotNil(t, gotCurrent.RevokedAt)
	require.Equal(t, rotateAt, *gotCurrent.RevokedAt)

	gotNext, err := repo.Get(ctx, next.Token)
	require.NoError(t, err)
	require.Equal(t, next.Token, gotNext.Token)
	require.Nil(t, gotNext.RevokedAt)
}

func TestRepoRotateReturnsNotFoundWhenCurrentTokenIsMissing(t *testing.T) {
	t.Parallel()

	repo, err := New(NewOptions(
		&fakeRefreshTokenClient{
			db: &fakeRefreshTokenDB{
				execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
					require.Equal(t, "oidc.refresh_tokens.Rotate.revoke", op)
					return pgconn.NewCommandTag("UPDATE 0"), nil
				},
			},
		},
		&fakeRefreshTokenTxManager{},
	))
	require.NoError(t, err)

	err = repo.Rotate(context.Background(), "missing", oidc.RefreshToken{Token: "refresh-2"}, time.Now().UTC())
	require.ErrorIs(t, err, oidc.ErrRefreshTokenNotFound)
}

type fakeRefreshTokenClient struct {
	db *fakeRefreshTokenDB
}

func (c *fakeRefreshTokenClient) DB() outbox.StoragePgsqlDBEngine {
	return c.db
}

func (c *fakeRefreshTokenClient) Close() error {
	return nil
}

type fakeRefreshTokenDB struct {
	getxFn  func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	execxFn func(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error)
	execFn  func(context.Context, string, string, ...any) (pgconn.CommandTag, error)
}

func (db *fakeRefreshTokenDB) ScanOne(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanOne call")
}

func (db *fakeRefreshTokenDB) ScanAll(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanAll call")
}

func (db *fakeRefreshTokenDB) ScanOnex(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanOnex call")
}

func (db *fakeRefreshTokenDB) ScanAllx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanAllx call")
}

func (db *fakeRefreshTokenDB) QueryRow(context.Context, string, string, ...any) pgx.Row {
	return nil
}

func (db *fakeRefreshTokenDB) Query(context.Context, string, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query call")
}

func (db *fakeRefreshTokenDB) Exec(
	ctx context.Context,
	operationName string,
	query string,
	arguments ...any,
) (pgconn.CommandTag, error) {
	if db.execFn == nil {
		return pgconn.NewCommandTag(""), nil
	}

	return db.execFn(ctx, operationName, query, arguments...)
}

func (db *fakeRefreshTokenDB) Getx(ctx context.Context, operationName string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error { //nolint:lll // autofix
	if db.getxFn == nil {
		return nil
	}

	return db.getxFn(ctx, operationName, dest, sqlizer)
}

func (db *fakeRefreshTokenDB) Selectx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected Selectx call")
}

func (db *fakeRefreshTokenDB) Execx(
	ctx context.Context,
	operationName string,
	sqlizer outbox.StoragePgsqlSqlizer,
) (pgconn.CommandTag, error) {
	if db.execxFn == nil {
		return pgconn.NewCommandTag(""), nil
	}

	return db.execxFn(ctx, operationName, sqlizer)
}

func (db *fakeRefreshTokenDB) SendBatch(context.Context, string, *pgx.Batch) pgx.BatchResults {
	return nil
}

func (db *fakeRefreshTokenDB) CopyFrom(
	context.Context,
	string,
	pgx.Identifier,
	[]string,
	pgx.CopyFromSource,
) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}

func (db *fakeRefreshTokenDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("unexpected BeginTx call")
}

func (db *fakeRefreshTokenDB) Ping(context.Context) error {
	return nil
}

func (db *fakeRefreshTokenDB) Pool() *pgxpool.Pool {
	return nil
}

func (db *fakeRefreshTokenDB) Close() {}

type fakeRefreshTokenTxManager struct {
	runInTxFn func(context.Context, func(context.Context) error) error
}

func (m *fakeRefreshTokenTxManager) RunInTx(ctx context.Context, fn func(context.Context) error) error {
	if m.runInTxFn != nil {
		return m.runInTxFn(ctx, fn)
	}

	return fn(ctx)
}

func (m *fakeRefreshTokenTxManager) ReadCommitted(
	ctx context.Context,
	_ pgx.TxAccessMode,
	fn outbox.StoragePgsqlFnCallback,
) error {
	return fn(ctx)
}

func (m *fakeRefreshTokenTxManager) RepeatableRead(
	ctx context.Context,
	_ pgx.TxAccessMode,
	fn outbox.StoragePgsqlFnCallback,
) error {
	return fn(ctx)
}

func (m *fakeRefreshTokenTxManager) Serializable(
	ctx context.Context,
	_ pgx.TxAccessMode,
	fn outbox.StoragePgsqlFnCallback,
) error {
	return fn(ctx)
}

func refreshTokenRowFromDomain(token oidc.RefreshToken) refreshTokenRow {
	var revokedAt sql.NullTime
	if token.RevokedAt != nil {
		revokedAt = sql.NullTime{Time: *token.RevokedAt, Valid: true}
	}

	return refreshTokenRow{
		SubjectID:       token.SubjectID,
		ClientID:        token.ClientID,
		SecurityVersion: token.SecurityVersion,
		Token:           token.Token,
		Scopes:          oidc.ScopeString(token.Scopes),
		AuthenticatedAt: token.AuthenticatedAt,
		ExpiresAt:       token.ExpiresAt,
		CreatedAt:       token.CreatedAt,
		RevokedAt:       revokedAt,
	}
}

var (
	_ outbox.StoragePgsqlClient    = (*fakeRefreshTokenClient)(nil)
	_ outbox.StoragePgsqlDBEngine  = (*fakeRefreshTokenDB)(nil)
	_ outbox.StoragePgsqlTxManager = (*fakeRefreshTokenTxManager)(nil)
)
