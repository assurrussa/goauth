//nolint:lll // Test fixtures keep expected request and error contracts together.
package goauth_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/assurrussa/goauth"
	authhttp "github.com/assurrussa/goauth/nethttp"
	"github.com/assurrussa/goauth/testkit"
)

const hardeningPassword = "Analysis-Disposable-Passphrase-2026" //nolint:gosec // isolated synthetic fixture credential

func TestSEC11AdvertisedExpiryMustNotExceedSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.Now = func() time.Time { return now }
		c.SessionTTL = time.Minute
		c.RefreshTTL = 10 * time.Minute
	})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := fixture.Runtime.Register(t.Context(), goauth.RegisterRequest{Email: "ttl@example.test", Password: hardeningPassword})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(50 * time.Second)
	rotated, err := fixture.Runtime.Refresh(t.Context(), registered.Tokens.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RefreshExpiresAt.After(rotated.Session.ExpiresAt) {
		t.Errorf("refresh advertises %s beyond the absolute session expiry", rotated.RefreshExpiresAt.Sub(rotated.Session.ExpiresAt))
	}
	if rotated.AccessExpiresAt.After(rotated.Session.ExpiresAt) {
		t.Errorf("access advertises %s beyond the absolute session expiry", rotated.AccessExpiresAt.Sub(rotated.Session.ExpiresAt))
	}
	now = now.Add(11 * time.Second)
	_, offlineErr := fixture.Runtime.VerifyJWT(t.Context(), rotated.AccessToken)
	_, onlineErr := fixture.Runtime.AuthenticateSession(t.Context(), rotated.AccessToken)
	_, refreshErr := fixture.Runtime.Refresh(t.Context(), rotated.RefreshToken)
	if offlineErr == nil || onlineErr == nil || refreshErr == nil {
		t.Fatal("credential usable after absolute expiry")
	}
}

type failingReads struct {
	goauth.RuntimeStore
	lookupErr     error
	introspectErr error
}

func (s *failingReads) FindLocalAccount(ctx context.Context, id goauth.IdentifierInput) (goauth.LocalAccountRecord, error) {
	if s.lookupErr != nil {
		return goauth.LocalAccountRecord{}, s.lookupErr
	}
	return s.RuntimeStore.FindLocalAccount(ctx, id)
}

func (s *failingReads) IntrospectSession(ctx context.Context, id string) (goauth.SessionSecurity, error) {
	if s.introspectErr != nil {
		return goauth.SessionSecurity{}, s.introspectErr
	}
	return s.RuntimeStore.IntrospectSession(ctx, id)
}

func TestW1InfrastructureErrorsRemainDistinguishable(t *testing.T) {
	var reads *failingReads
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		reads = &failingReads{RuntimeStore: c.Store}
		c.Store = reads
	})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := fixture.Runtime.Register(t.Context(), goauth.RegisterRequest{Email: "outage@example.test", Password: hardeningPassword})
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("synthetic storage outage")
	reads.lookupErr = fault
	reads.introspectErr = fault
	_, loginErr := fixture.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "outage@example.test"}, Password: hardeningPassword,
	}})
	_, sessionErr := fixture.Runtime.AuthenticateSession(t.Context(), registered.Tokens.AccessToken)
	for operation, got := range map[string]error{"login": loginErr, "authenticate": sessionErr} {
		response := httptest.NewRecorder()
		authhttp.WriteError(response, got)
		if !errors.Is(got, fault) {
			t.Errorf("%s loses storage cause: error=%v HTTP=%d", operation, got, response.Code)
		}
		if response.Code != 500 || strings.Contains(response.Body.String(), fault.Error()) {
			t.Errorf("%s exposes/misclassifies infrastructure failure: HTTP=%d", operation, response.Code)
		}
	}
}

type blockingPasswordHasher struct {
	block   atomic.Bool
	started chan struct{}
	release chan struct{}
}

func (*blockingPasswordHasher) HashPassword(string) (string, error) { return "test-only-hash", nil }
func (h *blockingPasswordHasher) VerifyPassword(string, string) error {
	if h.block.Load() {
		h.started <- struct{}{}
		<-h.release
	}
	return goauth.ErrInvalidCredentials
}

func TestPasswordHashBudgetIsSharedAndDoesNotQueue(t *testing.T) {
	h := &blockingPasswordHasher{started: make(chan struct{}, 4), release: make(chan struct{})}
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) { c.PasswordHasher = h })
	if err != nil {
		t.Fatal(err)
	}
	h.block.Store(true)
	var wg sync.WaitGroup
	for i := range goauth.DefaultMaxConcurrentPasswordHashes {
		wg.Go(func() {
			_, _ = fixture.Runtime.VerifyCredential(t.Context(), goauth.Credential{
				Identifier: goauth.IdentifierInput{Value: string(rune('a'+i)) + "@example.test"}, Password: "legacy",
			})
		})
	}
	defer func() { close(h.release); wg.Wait() }()
	for range goauth.DefaultMaxConcurrentPasswordHashes {
		select {
		case <-h.started:
		case <-time.After(5 * time.Second):
			t.Fatal("hash workers not admitted")
		}
	}
	_, err = fixture.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: goauth.Credential{
		Identifier: goauth.IdentifierInput{Value: "overflow@example.test"}, Password: "legacy",
	}})
	if !errors.Is(err, goauth.ErrPasswordHashOverloaded) {
		t.Fatalf("excess work queued/misclassified: %v", err)
	}
	w := httptest.NewRecorder()
	authhttp.WriteError(w, err)
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("overload is not retryable service failure")
	}
}

func TestLegacyPasswordVerificationDoesNotApplyNewIssuancePolicy(t *testing.T) {
	hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"short", "password123"} {
		phc, err := hasher.HashPassword(password)
		if err != nil {
			t.Fatal(err)
		}
		if err := hasher.VerifyPassword(phc, password); err != nil {
			t.Fatalf("legacy credential rejected: %v", err)
		}
		if err := goauth.DefaultPasswordPolicy().Validate(password); err == nil {
			t.Fatal("new issuance bypassed policy")
		}
	}
}

type observingHasher struct{ longest int }

func (*observingHasher) HashPassword(string) (string, error) {
	return "synthetic-test-only-hash", nil
}

func (h *observingHasher) VerifyPassword(_, password string) error {
	h.longest = max(h.longest, len(password))
	return goauth.ErrInvalidCredentials
}

func TestSEC05LoginBoundsPasswordBeforeHashing(t *testing.T) {
	hasher := &observingHasher{}
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) { c.PasswordHasher = hasher })
	if err != nil {
		t.Fatal(err)
	}
	_, err = fixture.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "hardening-missing@example.test"},
		Password:   strings.Repeat("A", 4096),
	}})
	if err == nil {
		t.Fatal("unexpected login success")
	}
	if hasher.longest > goauth.DefaultPasswordMaxLength {
		t.Errorf("oversized ASCII password reached PasswordHasher: length=%d policyMax=%d", hasher.longest, goauth.DefaultPasswordMaxLength)
	}
}
