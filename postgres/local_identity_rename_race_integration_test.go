//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

type renameRaceResult struct {
	view    goauth.LocalIdentityView
	err     error
	request goauth.RenameLocalIdentityRequest
}

func runLockedRenameRace(t *testing.T, db *sql.DB, runtime *postgres.Runtime, requests []goauth.RenameLocalIdentityRequest) []renameRaceResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	holder, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback() }()
	for _, request := range requests {
		var id goauth.SubjectID
		require.NoError(t, holder.QueryRowContext(ctx, `SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE`, request.SubjectID).Scan(&id))
	}
	started := make(chan int, len(requests))
	results := make(chan renameRaceResult, len(requests))
	for _, request := range requests {
		go func() {
			result := renameRaceResult{request: request}
			result.err = runtime.InAuthTransaction(ctx, func(txctx context.Context) error {
				executor, err := runtime.SQLExecutor(txctx)
				if err != nil {
					return err
				}
				var pid int
				if err = executor.QueryRowContext(txctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
					return err
				}
				started <- pid
				result.view, err = runtime.RenameLocalIdentity(txctx, request)
				return err
			})
			results <- result
		}()
	}
	for range requests {
		var pid int
		select {
		case pid = <-started:
		case <-ctx.Done():
			t.Fatal("rename transaction failed to reach its subject lock")
		}
		require.Eventually(t, func() bool {
			var waiting bool
			err := db.QueryRowContext(ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting)
			return err == nil && waiting
		}, 5*time.Second, 10*time.Millisecond, "each contender must block on the canonical subject lock")
	}
	require.NoError(t, holder.Commit())
	out := make([]renameRaceResult, 0, len(requests))
	for range requests {
		select {
		case result := <-results:
			out = append(out, result)
		case <-ctx.Done():
			t.Fatal("rename race did not terminate")
		}
	}
	return out
}

func TestPostgresLocalIdentityConcurrentRenamesHaveOneWinner(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	account := provisionRenameIdentity(t, db, runtime, "RaceOriginal")
	results := runLockedRenameRace(t, db, runtime, []goauth.RenameLocalIdentityRequest{
		renameRequest(account, "RaceOriginal", "RaceFirst"), renameRequest(account, "RaceOriginal", "RaceSecond"),
	})
	var winner goauth.LocalIdentityView
	successes := 0
	for _, result := range results {
		if result.err == nil {
			successes++
			winner = result.view
		} else {
			require.ErrorIs(t, result.err, goauth.ErrSecurityVersionMismatch)
			require.Zero(t, result.view)
		}
	}
	require.Equal(t, 1, successes)
	stored, err := runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, postgresIdentityScheme)
	require.NoError(t, err)
	assertRenameIdentifierPersisted(t, winner.Identifier, stored)
	require.Equal(t, account.Subject.SecurityVersion+1, winner.Account.Subject.SecurityVersion)
	require.Equal(t, 1, renameAuditCount(t, db, account.Subject.ID))
}

func TestPostgresLocalIdentityConcurrentRenamesCompeteForUniqueTarget(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	first := provisionRenameIdentity(t, db, runtime, "TargetRaceFirst")
	second := provisionRenameIdentity(t, db, runtime, "TargetRaceSecond")
	before := map[goauth.SubjectID]map[string]string{
		first.Subject.ID:  renameIdentitySnapshot(t, db, first.Subject.ID),
		second.Subject.ID: renameIdentitySnapshot(t, db, second.Subject.ID),
	}
	results := runLockedRenameRace(t, db, runtime, []goauth.RenameLocalIdentityRequest{
		renameRequest(first, "TargetRaceFirst", "SharedTarget"), renameRequest(second, "TargetRaceSecond", "SharedTarget"),
	})
	successes := 0
	for _, result := range results {
		if result.err == nil {
			successes++
			require.Equal(t, "SharedTarget", result.view.Identifier.NormalizedValue)
			require.Equal(t, result.request.ExpectedSecurityVersion+1, result.view.Account.Subject.SecurityVersion)
			require.Equal(t, 1, renameAuditCount(t, db, result.request.SubjectID))
		} else {
			require.ErrorIs(t, result.err, goauth.ErrIdentifierAlreadyExists)
			require.Zero(t, result.view)
			require.Equal(t, before[result.request.SubjectID], renameIdentitySnapshot(t, db, result.request.SubjectID))
		}
	}
	require.Equal(t, 1, successes)
	var owners int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_identifiers WHERE scheme=$1 AND normalized_value='SharedTarget'`, postgresIdentityScheme).Scan(&owners))
	require.Equal(t, 1, owners)
}

func TestPostgresLocalIdentityRenameABARejectsOriginalSnapshot(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := renamePostgresRuntime(t, db, nil)
	original := provisionRenameIdentity(t, db, runtime, "ABA-Original")
	first, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(original, "ABA-Original", "ABA-Changed"))
	require.NoError(t, err)
	second, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(first.Account, "ABA-Changed", "ABA-Original"))
	require.NoError(t, err)
	require.Equal(t, original.Subject.SecurityVersion+2, second.Account.Subject.SecurityVersion)
	before := renameIdentitySnapshot(t, db, original.Subject.ID)
	view, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(original, "ABA-Original", "ABA-Third"))
	require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
	require.Zero(t, view)
	require.Equal(t, before, renameIdentitySnapshot(t, db, original.Subject.ID))
	require.Equal(t, 2, renameAuditCount(t, db, original.Subject.ID))
}

type renameBarrierHasher struct {
	goauth.PasswordHasher
	hashArmed   atomic.Bool
	verifyArmed atomic.Bool
	entered     chan struct{}
	release     chan struct{}
	unblock     sync.Once
}

func (h *renameBarrierHasher) HashPassword(password string) (string, error) {
	if h.hashArmed.CompareAndSwap(true, false) {
		h.entered <- struct{}{}
		<-h.release
	}
	return h.PasswordHasher.HashPassword(password)
}

func (h *renameBarrierHasher) VerifyPassword(phc, password string) error {
	err := h.PasswordHasher.VerifyPassword(phc, password)
	if h.verifyArmed.CompareAndSwap(true, false) {
		h.entered <- struct{}{}
		<-h.release
	}
	return err
}

func (h *renameBarrierHasher) releaseWork() { h.unblock.Do(func() { close(h.release) }) }

func newRenameBarrierHasher(t *testing.T) *renameBarrierHasher {
	t.Helper()
	base, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	h := &renameBarrierHasher{PasswordHasher: base, entered: make(chan struct{}, 1), release: make(chan struct{})}
	t.Cleanup(h.releaseWork)
	return h
}

func waitRenameHasher(t *testing.T, hasher *renameBarrierHasher) {
	t.Helper()
	select {
	case <-hasher.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("password work did not reach the pre-lock barrier")
	}
}

func TestPostgresLocalIdentityRenameDeniesPausedCredentialProofEvenAfterABA(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	hasher := newRenameBarrierHasher(t)
	runtime := renamePostgresRuntime(t, db, func(config *goauth.Config) { config.PasswordHasher = hasher })
	account := provisionRenameIdentity(t, db, runtime, "PausedProofOriginal")
	hasher.verifyArmed.Store(true)
	type proofResult struct {
		proof *postgres.CredentialProof
		err   error
	}
	result := make(chan proofResult, 1)
	go func() {
		proof, err := runtime.PrepareCredential(t.Context(), goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: "PausedProofOriginal"}, Password: postgresRenamePassword,
		})
		result <- proofResult{proof, err}
	}()
	waitRenameHasher(t, hasher)
	changed, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(account, "PausedProofOriginal", "PausedProofChanged"))
	require.NoError(t, err)
	hasher.releaseWork()
	prepared := <-result
	require.NoError(t, prepared.err)
	assertDenied := func() {
		err := runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error {
			verified, err := runtime.RevalidateCredential(ctx, prepared.proof)
			require.Zero(t, verified)
			return err
		})
		require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	}
	assertDenied()
	_, err = runtime.RenameLocalIdentity(t.Context(), renameRequest(changed.Account, "PausedProofChanged", "PausedProofOriginal"))
	require.NoError(t, err)
	assertDenied()
	fresh, err := runtime.PrepareCredential(t.Context(), goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: postgresIdentityScheme, Value: "PausedProofOriginal"}, Password: postgresRenamePassword,
	})
	require.NoError(t, err)
	require.NoError(t, runtime.InAuthTransaction(t.Context(), func(ctx context.Context) error { _, err := runtime.RevalidateCredential(ctx, fresh); return err }))
}

func TestPostgresLocalIdentityRenameSerializesWithTrustedPasswordSet(t *testing.T) {
	for _, renameFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "rename-wins", false: "password-wins"}[renameFirst], func(t *testing.T) {
			db := integrationDB(t)
			resetSchema(t, db)
			hasher := newRenameBarrierHasher(t)
			runtime := renamePostgresRuntime(t, db, func(config *goauth.Config) { config.PasswordHasher = hasher })
			account := provisionRenameIdentity(t, db, runtime, "PasswordRaceOriginal")
			before := renameIdentitySnapshot(t, db, account.Subject.ID)
			hasher.hashArmed.Store(true)
			result := make(chan error, 1)
			go func() {
				_, err := runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
					SubjectID: account.Subject.ID, NewPassword: "Changed-Rename-Synthetic-Passphrase-43",
				})
				result <- err
			}()
			waitRenameHasher(t, hasher)
			if renameFirst {
				_, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(account, "PasswordRaceOriginal", "PasswordRaceChanged"))
				require.NoError(t, err)
				hasher.releaseWork()
				require.ErrorIs(t, <-result, goauth.ErrSecurityVersionMismatch)
				after := renameIdentitySnapshot(t, db, account.Subject.ID)
				require.Equal(t, before["auth_local_credentials"], after["auth_local_credentials"])
				require.Equal(t, 1, renameAuditCount(t, db, account.Subject.ID))
			} else {
				hasher.releaseWork()
				require.NoError(t, <-result)
				afterPassword := renameIdentitySnapshot(t, db, account.Subject.ID)
				view, err := runtime.RenameLocalIdentity(t.Context(), renameRequest(account, "PasswordRaceOriginal", "PasswordRaceChanged"))
				require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
				require.Zero(t, view)
				require.Equal(t, afterPassword, renameIdentitySnapshot(t, db, account.Subject.ID))
				require.Zero(t, renameAuditCount(t, db, account.Subject.ID))
			}
			stored, err := runtime.GetAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, account.Subject.SecurityVersion+1, stored.Subject.SecurityVersion)
		})
	}
}
