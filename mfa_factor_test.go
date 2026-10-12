package goauth_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/assurrussa/goauth"
)

func factorFixture(t *testing.T, domain string) (*goauth.MFAFactorCodec, goauth.SubjectID, goauth.MFAFactorRecord) {
	t.Helper()
	ring, err := goauth.NewKeyRing("key-1", goauth.Key{ID: "key-1", Material: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := goauth.NewMFAFactorCodec(ring, domain)
	if err != nil {
		t.Fatal(err)
	}
	subject := goauth.MustParseSubjectID("11111111-1111-4111-8111-111111111111")
	id, sealed, err := codec.Seal(subject, "factor-1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	return codec, subject, goauth.MFAFactorRecord{
		ID: "factor-1", Revision: 1, Enabled: true, KeyID: id,
		Ciphertext: sealed, LastStep: -1,
	}
}

func TestMFAFactorLegacyCiphertextAndDigest(t *testing.T) {
	codec, subject, factor := factorFixture(t, "authhub/mfa")
	block, err := aes.NewCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	aad := []byte("authhub/mfa/totp/v1\x00" + subject.String() + "\x00factor-1")
	//nolint:gosec // Random-nonce GCM generates the nonce, matching the existing AuthHub format.
	ciphertext := legacy.Seal(nil, nil, plain, aad)
	opened, err := codec.Open(subject, factor.ID, factor.KeyID, ciphertext)
	if err != nil || !bytes.Equal(opened, plain) {
		t.Fatalf("legacy open: %v", err)
	}
	clear(opened)
	code := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	got, err := codec.RecoveryDigest(subject, factor.ID, code)
	want := sha256.Sum256([]byte("authhub/mfa/recovery/v1\x00" + subject.String() + "\x00factor-1\x00" + code))
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("legacy digest: %v", err)
	}
}

func TestMFAFactorBindingAndKeysFailClosed(t *testing.T) {
	codec, subject, f := factorFixture(t, "goauth/mfa")
	otherCodec, _, _ := factorFixture(t, "authhub/mfa")
	for name, run := range map[string]func() error{
		testSubjectMutation: func() error { _, e := codec.Open(goauth.NewSubjectID(), f.ID, f.KeyID, f.Ciphertext); return e },
		"factor binding":    func() error { _, e := codec.Open(subject, "other", f.KeyID, f.Ciphertext); return e },
		testKeyLabel:        func() error { _, e := codec.Open(subject, f.ID, "missing-mfa-key", f.Ciphertext); return e },
		"domain":            func() error { _, e := otherCodec.Open(subject, f.ID, f.KeyID, f.Ciphertext); return e },
		"truncated":         func() error { _, e := codec.Open(subject, f.ID, f.KeyID, f.Ciphertext[:5]); return e },
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(run(), goauth.ErrMFAUnavailable) {
				t.Fatal("accepted invalid binding")
			}
		})
	}
}

func TestMFATOTPStepRFCVectorAndSyntax(t *testing.T) {
	//nolint:gosec // Public RFC 6238 test vector, never an installed authentication credential.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for _, seconds := range []int64{29, 59, 89} {
		step, ok, err := goauth.MFATOTPStep(secret, "287082", time.Unix(seconds, 0))
		if err != nil || !ok || step != 1 {
			t.Fatalf("at %d: %d %v %v", seconds, step, ok, err)
		}
	}
	for _, code := range []string{"28708", "2870820", " 287082", "２８７０８２", testNonNumericCode} {
		_, ok, err := goauth.MFATOTPStep(secret, code, time.Unix(59, 0))
		if err != nil || ok {
			t.Fatalf("accepted %q", code)
		}
	}
	_, ok, err := goauth.MFATOTPStep(secret, "287082", time.Unix(119, 0))
	if err != nil || ok {
		t.Fatal("accepted outside skew window")
	}
}

type factorStoreFixture struct {
	attempts int
	limit    int
	step     int64
	recovery bool
	conflict bool
}

func (s *factorStoreFixture) LockMFAFactor(context.Context, goauth.SubjectID) (goauth.MFAFactorRecord, error) {
	return goauth.MFAFactorRecord{}, nil
}

func (s *factorStoreFixture) TakeMFAAttempt(context.Context, goauth.SubjectID) (bool, error) {
	if s.attempts >= s.limit {
		return false, nil
	}
	s.attempts++
	return true, nil
}

func (s *factorStoreFixture) ConsumeMFARecovery(context.Context, goauth.SubjectID, string, int64, []byte) (bool, error) {
	if !s.recovery || s.conflict {
		return false, nil
	}
	s.recovery = false
	return true, nil
}

func (s *factorStoreFixture) AdvanceMFAStep(_ context.Context, _ goauth.SubjectID, _ string, _ int64,
	previous, next int64,
) (bool, error) {
	if s.conflict || s.step != previous || next <= s.step {
		return false, nil
	}
	s.step = next
	return true, nil
}

func TestMFAFactorConsumesOnlyOnceAndSpendsDenials(t *testing.T) {
	codec, subject, f := factorFixture(t, "goauth/mfa")
	store := &factorStoreFixture{limit: 3, step: -1}
	for _, want := range []goauth.MFAFactorDecision{
		goauth.MFAFactorVerified, goauth.MFAFactorDenied,
		goauth.MFAFactorDenied, goauth.MFAFactorRateLimited,
	} {
		got, err := goauth.VerifyMFAFactorLocked(context.Background(), store, codec, subject, f, "287082", time.Unix(59, 0))
		if err != nil || got != want {
			t.Fatalf("got %v, %v; want %v", got, err, want)
		}
	}
	if store.attempts != 3 || store.step != 1 {
		t.Fatal("bad durable effects")
	}
}

func TestMFAFactorRecoveryAndMissingKey(t *testing.T) {
	codec, subject, f := factorFixture(t, "goauth/mfa")
	code, err := goauth.NewMFARecoveryCode()
	if err != nil || !goauth.IsMFARecoveryCode(code) {
		t.Fatalf("generate: %v", err)
	}
	store := &factorStoreFixture{limit: 10, recovery: true}
	for _, want := range []goauth.MFAFactorDecision{goauth.MFAFactorVerified, goauth.MFAFactorDenied} {
		got, err := goauth.VerifyMFAFactorLocked(context.Background(), store, codec, subject, f, code, time.Now())
		if err != nil || got != want {
			t.Fatalf("got %v, %v; want %v", got, err, want)
		}
	}
	f.KeyID = "missing-mfa-key"
	store.recovery = true
	got, err := goauth.VerifyMFAFactorLocked(context.Background(), store, codec, subject, f, code, time.Now())
	if !errors.Is(err, goauth.ErrMFAUnavailable) || got != goauth.MFAFactorDenied || !store.recovery {
		t.Fatal("missing key did not fail closed")
	}
}

func TestMFAFactorCASDenialAndDisabledFactor(t *testing.T) {
	codec, subject, f := factorFixture(t, "goauth/mfa")
	store := &factorStoreFixture{limit: 10, step: -1, conflict: true}
	got, err := goauth.VerifyMFAFactorLocked(context.Background(), store, codec, subject, f, "287082", time.Unix(59, 0))
	if err != nil || got != goauth.MFAFactorDenied || store.attempts != 1 || store.step != -1 {
		t.Fatal("CAS conflict accepted or attempt refunded")
	}
	f.Enabled = false
	got, err = goauth.VerifyMFAFactorLocked(context.Background(), store, codec, subject, f, "287082", time.Unix(59, 0))
	if err != nil || got != goauth.MFAFactorDenied || store.attempts != 1 {
		t.Fatal("disabled factor accepted")
	}
}
