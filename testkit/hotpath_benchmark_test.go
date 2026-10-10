//nolint:testpackage // Bounded benchmark resets need the existing testkit snapshot state.
package testkit

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/assurrussa/goauth"
)

const (
	hotPathEmail    = "hotpath@example.test"
	hotPathPassword = "Hotpath-Only-Passphrase-2026"
)

// BenchmarkRuntimeHotPaths measures sequential, in-memory user-realm operations.
// It is not a PostgreSQL, HTTP, concurrent-load, or host-membership baseline.
func BenchmarkRuntimeHotPaths(b *testing.B) {
	b.Run("testkit/user/Login/argon2id_m19456_t2_p1", benchmarkHotPathLogin)
	b.Run("testkit/user/VerifyJWT/offline_HS256", benchmarkHotPathVerifyJWT)
	b.Run("testkit/user/AuthenticateSession/storage_HS256", benchmarkHotPathAuthenticateSession)
	b.Run("testkit/user/Refresh/success_first_rotation", benchmarkHotPathRefresh)
}

func benchmarkHotPathLogin(b *testing.B) {
	b.StopTimer()
	fixture, request, subjectID := newHotPathFixture(b)
	baseline := fixture.Store.snapshot()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		restoreHotPathWrites(fixture.Store, baseline)
		b.StartTimer()
		result, err := fixture.Runtime.Login(ctx, request)
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		if result.Account.Subject.ID != subjectID {
			b.Fatal("login returned a different subject")
		}
		checkHotPathTokens(b, result.Tokens, subjectID)
		checkHotPathState(b, fixture, 1)
	}
}

func benchmarkHotPathVerifyJWT(b *testing.B) {
	benchmarkHotPathSession(b, false)
}

func benchmarkHotPathAuthenticateSession(b *testing.B) {
	benchmarkHotPathSession(b, true)
}

func benchmarkHotPathSession(b *testing.B, introspect bool) {
	b.Helper()
	b.StopTimer()
	fixture, request, subjectID := newHotPathFixture(b)
	ctx := context.Background()
	login, err := fixture.Runtime.Login(ctx, request)
	if err != nil {
		b.Fatal(err)
	}
	checkHotPathTokens(b, login.Tokens, subjectID)
	verify := fixture.Runtime.VerifyJWT
	if introspect {
		verify = fixture.Runtime.AuthenticateSession
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.StartTimer()
	for range b.N {
		auth, err := verify(ctx, login.Tokens.AccessToken)
		if err != nil {
			b.Fatal(err)
		}
		if auth.SubjectID != subjectID || auth.SessionID != login.Tokens.Session.ID ||
			auth.Realm != goauth.RealmUser || auth.Scope != goauth.SessionScopeAuthenticated || auth.SecurityVersion != 1 {
			b.Fatal("session verification returned unexpected authentication")
		}
	}
	b.StopTimer()
	checkHotPathState(b, fixture, 1)
}

func benchmarkHotPathRefresh(b *testing.B) {
	b.StopTimer()
	fixture, request, subjectID := newHotPathFixture(b)
	ctx := context.Background()
	login, err := fixture.Runtime.Login(ctx, request)
	if err != nil {
		b.Fatal(err)
	}
	checkHotPathTokens(b, login.Tokens, subjectID)
	baseline := fixture.Store.snapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		// Restore a deep copy of the unconsumed token, not the previous result.
		// Every operation starts with one session, one family, and one token.
		restoreHotPathWrites(fixture.Store, baseline)
		b.StartTimer()
		tokens, err := fixture.Runtime.Refresh(ctx, login.Tokens.RefreshToken)
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		checkHotPathTokens(b, tokens, subjectID)
		if tokens.RefreshToken == login.Tokens.RefreshToken || tokens.Session.ID != login.Tokens.Session.ID {
			b.Fatal("refresh did not rotate within the original session")
		}
		checkHotPathState(b, fixture, 2)
		var consumed int
		for _, token := range fixture.Store.refresh {
			if token.ConsumedAt != nil {
				consumed++
			}
		}
		if consumed != 1 {
			b.Fatal("refresh did not consume exactly one token")
		}
	}
}

func newHotPathFixture(b *testing.B) (*Fixture, goauth.LoginRequest, goauth.SubjectID) {
	b.Helper()
	now := time.Date(2026, time.October, 10, 0, 0, 0, 0, time.UTC)
	hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{
		MemoryKiB: 19456, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	if err != nil {
		b.Fatal(err)
	}
	fixture, err := NewRuntime(func(config *goauth.Config) {
		config.Now = func() time.Time { return now }
		config.PasswordHasher = hasher
		config.MaxConcurrentPasswordHashes = 4
	})
	if err != nil {
		b.Fatal(err)
	}
	phc, err := hasher.HashPassword(hotPathPassword)
	if err != nil {
		b.Fatal(err)
	}
	subjectID := goauth.NewSubjectID()
	_, err = fixture.Store.CreateLocalAccount(context.Background(), goauth.LocalAccountRecord{
		Account: goauth.Account{
			Subject: goauth.Subject{
				ID: subjectID, Status: goauth.SubjectStatusActive, SecurityVersion: 1, CreatedAt: now, UpdatedAt: now,
			},
			PrimaryEmail: goauth.Identifier{
				ID: "hotpath-email", SubjectID: subjectID, Scheme: goauth.IdentifierSchemeEmail,
				DisplayValue: hotPathEmail, NormalizedValue: hotPathEmail, VerifiedAt: &now, CreatedAt: now, UpdatedAt: now,
			},
		},
		PasswordPHC: phc, PasswordInputPolicy: goauth.PasswordInputPolicyUnicode,
	})
	if err != nil {
		b.Fatal(err)
	}
	request := goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: hotPathEmail},
			Password:   hotPathPassword,
		},
		Realm: goauth.RealmUser,
	}
	return fixture, request, subjectID
}

// Restore only state these successful paths can mutate. The account/credential
// cardinality remains one; fixture transactions still clone that fixed dataset.
// No mutex is copied, and no reset work or allocation is timed. Serial use only.
func restoreHotPathWrites(store, baseline *Store) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.audits = append([]goauth.SecurityEvent(nil), baseline.audits...)
	store.sessions = maps.Clone(baseline.sessions)
	store.families = copyPointers(baseline.families)
	store.refresh = copyPointers(baseline.refresh)
	store.rateEvents = make(map[string][]time.Time, len(baseline.rateEvents))
	for key, events := range baseline.rateEvents {
		store.rateEvents[key] = append([]time.Time(nil), events...)
	}
}

func checkHotPathTokens(b *testing.B, tokens goauth.TokenPair, subjectID goauth.SubjectID) {
	b.Helper()
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.Session.ID == "" ||
		tokens.Session.SubjectID != subjectID || tokens.Session.Realm != goauth.RealmUser ||
		tokens.Session.Scope != goauth.SessionScopeAuthenticated || tokens.Session.SecurityVersion != 1 {
		b.Fatal("operation did not return authenticated user tokens")
	}
}

func checkHotPathState(b *testing.B, fixture *Fixture, refreshCount int) {
	b.Helper()
	store := fixture.Store
	if len(store.accounts) != 1 || len(store.identifiers) != 1 || len(store.passwords) != 1 ||
		len(store.sessions) != 1 || len(store.families) != 1 || len(store.refresh) != refreshCount ||
		len(store.audits) != 0 || len(fixture.Events.events) != 0 || len(store.rateEvents) != 1 {
		b.Fatal("benchmark fixture cardinality changed")
	}
	for _, events := range store.rateEvents {
		if len(events) != 1 {
			b.Fatal("login rate-limit history accumulated between operations")
		}
	}
}
