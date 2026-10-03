//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

func raceSubjectMutations(t *testing.T, db *sql.DB, runtime *postgres.Runtime, id goauth.SubjectID, mutations []func(context.Context) error) []error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	holder, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback() }()
	var locked goauth.SubjectID
	require.NoError(t, holder.QueryRowContext(ctx, `SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE`, id).Scan(&locked))
	started := make(chan int, len(mutations))
	results := make(chan error, len(mutations))
	for _, mutation := range mutations {
		go func() {
			results <- runtime.InAuthTransaction(ctx, func(txctx context.Context) error {
				executor, err := runtime.SQLExecutor(txctx)
				if err != nil {
					return err
				}
				var pid int
				if err = executor.QueryRowContext(txctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					return err
				}
				started <- pid
				return mutation(txctx)
			})
		}()
	}
	for range mutations {
		select {
		case pid := <-started:
			require.Eventually(t, func() bool {
				var blocked bool
				err := db.QueryRowContext(ctx,
					`SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&blocked)
				return err == nil && blocked
			}, 5*time.Second, 10*time.Millisecond)
		case <-ctx.Done():
			t.Fatal("subject mutation did not start")
		}
	}
	require.NoError(t, holder.Commit())
	collected := make([]error, 0, len(mutations))
	for range mutations {
		select {
		case err := <-results:
			collected = append(collected, err)
		case <-ctx.Done():
			t.Fatal("subject mutation did not complete")
		}
	}
	return collected
}

func TestPostgresSubjectRetirementSerializesWithRenameStatusAndRetirement(t *testing.T) {
	for _, other := range []string{"rename", "status", "retirement"} {
		t.Run(other, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			runtime := renamePostgresRuntime(t, db, nil)
			account := provisionRenameIdentity(t, db, runtime, "RetireRace")
			retire := func(ctx context.Context) error {
				_, err := runtime.RetireLocalIdentity(ctx, retirementRequest(account, "RetireRace"))
				return err
			}
			competitor := func(ctx context.Context) error {
				switch other {
				case "rename":
					_, err := runtime.RenameLocalIdentity(ctx, renameRequest(account, "RetireRace", "RaceChanged"))
					return err
				case "status":
					_, err := runtime.SetSubjectStatus(ctx, account.Subject.ID, goauth.SubjectStatusSuspended)
					return err
				default:
					return retire(ctx)
				}
			}
			outcomes := raceSubjectMutations(t, db, runtime, account.Subject.ID, []func(context.Context) error{retire, competitor})
			successes := 0
			for _, err := range outcomes {
				if err == nil {
					successes++
				} else {
					require.True(t, errors.Is(err, goauth.ErrSubjectRetired) || errors.Is(err, goauth.ErrSecurityVersionMismatch), "unexpected loser: %v", err)
				}
			}
			require.Equal(t, 1, successes)
			current, err := runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, account.Subject.SecurityVersion+1, current.Account.Subject.SecurityVersion)
			if current.RetiredAt != nil {
				require.Equal(t, goauth.SubjectStatusDisabled, current.Account.Subject.Status)
				require.Equal(t, 1, retirementAuditCount(t, db, account.Subject.ID))
			}
		})
	}
}

func TestPostgresSubjectRetirementDeniesPausedPasswordAndProof(t *testing.T) {
	for _, operation := range []string{"password", "proof"} {
		t.Run(operation, func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			hasher := newRenameBarrierHasher(t)
			runtime := renamePostgresRuntime(t, db, func(c *goauth.Config) { c.PasswordHasher = hasher })
			account := provisionRenameIdentity(t, db, runtime, "RetirePaused")
			type result struct {
				proof *postgres.CredentialProof
				err   error
			}
			pending := make(chan result, 1)
			if operation == "password" {
				hasher.hashArmed.Store(true)
				go func() {
					_, err := runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
						SubjectID: account.Subject.ID, NewPassword: "Retirement-Paused-Synthetic-Passphrase-42",
					})
					pending <- result{err: err}
				}()
			} else {
				hasher.verifyArmed.Store(true)
				go func() {
					proof, err := runtime.PrepareCredential(t.Context(), goauth.Credential{
						Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: "RetirePaused"}, Password: postgresRenamePassword,
					})
					pending <- result{proof: proof, err: err}
				}()
			}
			waitRenameHasher(t, hasher)
			_, err := runtime.RetireLocalIdentity(t.Context(), retirementRequest(account, "RetirePaused"))
			require.NoError(t, err)
			hasher.releaseWork()
			finished := <-pending
			if operation == "password" {
				require.ErrorIs(t, finished.err, goauth.ErrSubjectRetired)
			} else {
				require.NoError(t, finished.err)
				replacement := provisionRenameIdentity(t, db, runtime, "RetirePaused")
				require.NotEqual(t, account.Subject.ID, replacement.Subject.ID)
				err := runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
					verified, err := runtime.RevalidateCredential(ctx, finished.proof)
					require.Zero(t, verified)
					return err
				})
				require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
			}
			var credentials int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_local_credentials WHERE subject_id=$1`, account.Subject.ID).Scan(&credentials))
			require.Zero(t, credentials)
		})
	}
}

func TestPostgresSubjectRetirementReleaseBecomesReusableOnlyOnCommit(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{true: "commit", false: "rollback"}[commit], func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			runtime := identityPostgresRuntime(t, db)
			account := provisionRenameIdentity(t, db, runtime, "RetireRelease")
			before := renameIdentitySnapshot(t, db, account.Subject.ID)
			type result struct {
				account goauth.Account
				err     error
			}
			pending := make(chan result, 1)
			started := make(chan int, 1)
			rollback := errors.New("retirement deliberately rolled back")
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			err := runtime.InAuthTransaction(ctx, func(txctx context.Context) error {
				_, err := runtime.RetireLocalIdentity(txctx, retirementRequest(account, "RetireRelease"))
				if err != nil {
					return err
				}
				go func() {
					var replacement goauth.Account
					err := runtime.InAuthTransaction(ctx, func(createctx context.Context) error {
						executor, err := runtime.SQLExecutor(createctx)
						if err != nil {
							return err
						}
						var pid int
						if err = executor.QueryRowContext(createctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
							return err
						}
						started <- pid
						replacement, err = runtime.ImportLocalIdentity(createctx, goauth.ImportLocalIdentityRequest{
							SubjectID: goauth.NewSubjectID(), Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: "RetireRelease"},
							PasswordPHC: postgresLegacyPHC(postgresRenamePassword), PasswordInputPolicy: goauth.PasswordInputPolicyLegacyBytes256, Status: goauth.SubjectStatusActive,
						})
						return err
					})
					pending <- result{replacement, err}
				}()
				select {
				case pid := <-started:
					require.Eventually(t, func() bool {
						var blocked bool
						err := db.QueryRowContext(ctx,
							`SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&blocked)
						return err == nil && blocked
					}, 5*time.Second, 10*time.Millisecond)
				case <-ctx.Done():
					return ctx.Err()
				}
				if !commit {
					return rollback
				}
				return nil
			})
			var created result
			select {
			case created = <-pending:
			case <-ctx.Done():
				t.Fatal("competing creation did not finish")
			}
			if commit {
				require.NoError(t, err)
				require.NoError(t, created.err)
				require.NotEqual(t, account.Subject.ID, created.account.Subject.ID)
				cleanupRenameSubject(t, db, created.account.Subject.ID)
			} else {
				require.ErrorIs(t, err, rollback)
				require.ErrorIs(t, created.err, goauth.ErrIdentifierAlreadyExists)
				require.Equal(t, before, renameIdentitySnapshot(t, db, account.Subject.ID))
			}
		})
	}
}
