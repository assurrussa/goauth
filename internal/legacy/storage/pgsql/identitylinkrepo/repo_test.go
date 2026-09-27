//nolint:testpackage // internal test
package identitylinkrepo

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
	"github.com/assurrussa/goauth/internal/legacy/sso"
)

func TestRepoUpsertGetAndList(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	verified := true
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174030")

	first := sso.IdentityLink{
		SubjectID:     subjectID,
		SubjectKind:   authcore.SubjectKindUser,
		Issuer:        "https://issuer.example.com",
		ExternalSub:   "sub-1",
		AuthSource:    sso.AuthSourceEmbeddedOIDC,
		Email:         "first@example.com",
		EmailVerified: &verified,
		LastSeenAt:    now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	second := sso.IdentityLink{
		SubjectID:     subjectID,
		SubjectKind:   authcore.SubjectKindUser,
		Issuer:        "https://issuer.example.com",
		ExternalSub:   "sub-2",
		AuthSource:    sso.AuthSourceEmbeddedOIDC,
		Email:         "second@example.com",
		EmailVerified: &verified,
		LastSeenAt:    now.Add(time.Minute),
		CreatedAt:     now.Add(time.Minute),
		UpdatedAt:     now.Add(time.Minute),
	}

	var stored []sso.IdentityLink
	pendingUpserts := []sso.IdentityLink{first, second}
	db := &fakeIdentityLinkDB{
		execxFn: func(_ context.Context, op string, _ outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error) {
			require.Equal(t, "sso.identity_links.Upsert", op)
			require.NotEmpty(t, pendingUpserts)

			next := pendingUpserts[0]
			pendingUpserts = pendingUpserts[1:]
			stored = upsertIdentityLink(stored, next)

			return pgconn.NewCommandTag("INSERT 0 1"), nil
		},
		getxFn: func(_ context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
			require.Equal(t, "sso.identity_links.GetByExternalSubject", op)

			_, args, err := sqlizer.ToSql()
			require.NoError(t, err)
			require.Len(t, args, 2)

			firstArg, _ := args[0].(string)
			secondArg, _ := args[1].(string)
			for _, link := range stored {
				if (link.Issuer == firstArg && link.ExternalSub == secondArg) ||
					(link.Issuer == secondArg && link.ExternalSub == firstArg) {
					record, ok := dest.(*rowModel)
					require.True(t, ok)
					*record = rowModelFromIdentityLink(link)
					return nil
				}
			}

			return pgx.ErrNoRows
		},
		selectxFn: func(_ context.Context, op string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error {
			require.Equal(t, "sso.identity_links.ListBySubject", op)

			_, args, err := sqlizer.ToSql()
			require.NoError(t, err)
			require.Len(t, args, 1)

			subjectIDStr, ok := args[0].(string)
			require.True(t, ok)
			subjectID := authcore.MustParseSubjectIDString(subjectIDStr)
			rows := make([]rowModel, 0, len(stored))
			for _, link := range stored {
				if link.SubjectID == subjectID {
					rows = append(rows, rowModelFromIdentityLink(link))
				}
			}
			sort.Slice(rows, func(i, j int) bool {
				return rows[i].CreatedAt.Before(rows[j].CreatedAt)
			})

			records, ok := dest.(*[]rowModel)
			require.True(t, ok)
			*records = rows

			return nil
		},
	}

	repo, err := New(&fakeIdentityLinkClient{db: db})
	require.NoError(t, err)

	require.NoError(t, repo.Upsert(ctx, first))
	require.NoError(t, repo.Upsert(ctx, second))

	got, err := repo.GetByExternalSubject(ctx, first.Issuer, first.ExternalSub)
	require.NoError(t, err)
	require.Equal(t, first.SubjectID, got.SubjectID)
	require.Equal(t, first.ExternalSub, got.ExternalSub)
	require.Equal(t, first.Email, got.Email)
	require.NotNil(t, got.EmailVerified)
	require.True(t, *got.EmailVerified)

	links, err := repo.ListBySubject(ctx, first.SubjectID)
	require.NoError(t, err)
	require.Len(t, links, 2)
	require.Equal(t, first.ExternalSub, links[0].ExternalSub)
	require.Equal(t, second.ExternalSub, links[1].ExternalSub)
}

func TestRepoGetByExternalSubjectReturnsNotFound(t *testing.T) {
	t.Parallel()

	repo, err := New(&fakeIdentityLinkClient{
		db: &fakeIdentityLinkDB{
			getxFn: func(_ context.Context, op string, _ any, _ outbox.StoragePgsqlSqlizer) error {
				require.Equal(t, "sso.identity_links.GetByExternalSubject", op)
				return pgx.ErrNoRows
			},
		},
	})
	require.NoError(t, err)

	_, err = repo.GetByExternalSubject(context.Background(), "https://issuer.example.com", "missing")
	require.ErrorIs(t, err, sso.ErrIdentityLinkNotFound)
}

type fakeIdentityLinkClient struct {
	db *fakeIdentityLinkDB
}

func (c *fakeIdentityLinkClient) DB() outbox.StoragePgsqlDBEngine {
	return c.db
}

func (c *fakeIdentityLinkClient) Close() error {
	return nil
}

type fakeIdentityLinkDB struct {
	getxFn    func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	selectxFn func(context.Context, string, any, outbox.StoragePgsqlSqlizer) error
	execxFn   func(context.Context, string, outbox.StoragePgsqlSqlizer) (pgconn.CommandTag, error)
}

func (db *fakeIdentityLinkDB) ScanOne(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanOne call")
}

func (db *fakeIdentityLinkDB) ScanAll(context.Context, string, any, string, ...any) error {
	return errors.New("unexpected ScanAll call")
}

func (db *fakeIdentityLinkDB) ScanOnex(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanOnex call")
}

func (db *fakeIdentityLinkDB) ScanAllx(context.Context, string, any, outbox.StoragePgsqlSqlizer) error {
	return errors.New("unexpected ScanAllx call")
}

func (db *fakeIdentityLinkDB) QueryRow(context.Context, string, string, ...any) pgx.Row {
	return nil
}

func (db *fakeIdentityLinkDB) Query(context.Context, string, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query call")
}

func (db *fakeIdentityLinkDB) Exec(context.Context, string, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), nil
}

func (db *fakeIdentityLinkDB) Getx(ctx context.Context, operationName string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error { //nolint:lll // autofix
	if db.getxFn == nil {
		return nil
	}

	return db.getxFn(ctx, operationName, dest, sqlizer)
}

func (db *fakeIdentityLinkDB) Selectx(ctx context.Context, operationName string, dest any, sqlizer outbox.StoragePgsqlSqlizer) error { //nolint:lll // autofix
	if db.selectxFn == nil {
		return nil
	}

	return db.selectxFn(ctx, operationName, dest, sqlizer)
}

func (db *fakeIdentityLinkDB) Execx(
	ctx context.Context,
	operationName string,
	sqlizer outbox.StoragePgsqlSqlizer,
) (pgconn.CommandTag, error) {
	if db.execxFn == nil {
		return pgconn.NewCommandTag(""), nil
	}

	return db.execxFn(ctx, operationName, sqlizer)
}

func (db *fakeIdentityLinkDB) SendBatch(context.Context, string, *pgx.Batch) pgx.BatchResults {
	return nil
}

func (db *fakeIdentityLinkDB) CopyFrom(
	context.Context,
	string,
	pgx.Identifier,
	[]string,
	pgx.CopyFromSource,
) (int64, error) {
	return 0, errors.New("unexpected CopyFrom call")
}

func (db *fakeIdentityLinkDB) BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error) {
	return nil, errors.New("unexpected BeginTx call")
}

func (db *fakeIdentityLinkDB) Ping(context.Context) error {
	return nil
}

func (db *fakeIdentityLinkDB) Pool() *pgxpool.Pool {
	return nil
}

func (db *fakeIdentityLinkDB) Close() {}

func rowModelFromIdentityLink(link sso.IdentityLink) rowModel {
	var email sql.NullString
	if link.Email != "" {
		email = sql.NullString{String: link.Email, Valid: true}
	}

	var emailVerified sql.NullBool
	if link.EmailVerified != nil {
		emailVerified = sql.NullBool{Bool: *link.EmailVerified, Valid: true}
	}

	return rowModel{
		SubjectID:     link.SubjectID,
		SubjectKind:   string(link.SubjectKind),
		Issuer:        link.Issuer,
		ExternalSub:   link.ExternalSub,
		AuthSource:    string(link.AuthSource),
		Email:         email,
		EmailVerified: emailVerified,
		LastSeenAt:    link.LastSeenAt,
		CreatedAt:     link.CreatedAt,
		UpdatedAt:     link.UpdatedAt,
	}
}

func upsertIdentityLink(links []sso.IdentityLink, next sso.IdentityLink) []sso.IdentityLink {
	for i := range links {
		if links[i].Issuer == next.Issuer && links[i].ExternalSub == next.ExternalSub {
			links[i] = next
			return links
		}
	}

	return append(links, next)
}

var (
	_ outbox.StoragePgsqlClient   = (*fakeIdentityLinkClient)(nil)
	_ outbox.StoragePgsqlDBEngine = (*fakeIdentityLinkDB)(nil)
)
