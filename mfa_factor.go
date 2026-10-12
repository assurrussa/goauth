package goauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var ErrMFAUnavailable = errors.New("MFA unavailable")

// MFAFactorRecord is durable encrypted state. Revision advances on every
// enrollment replacement, disable, or recovery-code regeneration.
type MFAFactorRecord struct {
	ID         string
	Revision   int64
	Enabled    bool
	KeyID      string
	Ciphertext []byte
	LastStep   int64
}

// MFAFactorStore joins a subject-locked auth transaction. Expected business
// denials commit their attempt budget. Consume operations must compare the exact
// enabled factor ID and revision and atomically consume the digest/step.
type MFAFactorStore interface {
	LockMFAFactor(ctx context.Context, subject SubjectID) (MFAFactorRecord, error)
	TakeMFAAttempt(ctx context.Context, subject SubjectID) (bool, error)
	ConsumeMFARecovery(ctx context.Context, subject SubjectID, factorID string, revision int64, digest []byte) (bool, error)
	AdvanceMFAStep(ctx context.Context, subject SubjectID, factorID string, revision, previous, next int64) (bool, error)
}
type MFAFactorDecision uint8

const (
	MFAFactorDenied MFAFactorDecision = iota
	MFAFactorVerified
	MFAFactorRateLimited
)

// MFAFactorCodec retains an explicit persistent domain. Existing AuthHub rows
// use authhub/mfa; native local factors use goauth/mfa. Keep historical keys.
type MFAFactorCodec struct {
	keys   KeyRing
	domain string
}

func NewMFAFactorCodec(keys KeyRing, domain string) (*MFAFactorCodec, error) {
	if !validMFADomain(domain) {
		return nil, ErrMFAUnavailable
	}
	key, err := keys.Active()
	if err != nil {
		return nil, ErrMFAUnavailable
	}
	clear(key.Material)
	for _, id := range keys.IDs() {
		if len(id) > 64 {
			return nil, ErrMFAUnavailable
		}
	}
	return &MFAFactorCodec{keys: keys, domain: domain}, nil
}

func validMFADomain(domain string) bool {
	if domain == "" || len(domain) > 128 || strings.HasSuffix(domain, "/") {
		return false
	}
	for _, r := range domain {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func (c *MFAFactorCodec) aead(keyID string) (cipher.AEAD, error) {
	if c == nil || !validMFADomain(c.domain) {
		return nil, ErrMFAUnavailable
	}
	key, err := c.keys.Get(keyID)
	if err != nil {
		return nil, ErrMFAUnavailable
	}
	defer clear(key.Material)
	block, err := aes.NewCipher(key.Material)
	if err != nil {
		return nil, ErrMFAUnavailable
	}
	return cipher.NewGCMWithRandomNonce(block)
}
func (c *MFAFactorCodec) CheckKey(keyID string) error { _, err := c.aead(keyID); return err }
func validMFAFactorBinding(subject SubjectID, factor string) bool {
	return !subject.IsZero() && factor != "" && len(factor) <= 128 && !strings.ContainsRune(factor, '\x00')
}

func (c *MFAFactorCodec) additionalData(subject SubjectID, factor string) []byte {
	return []byte(c.domain + "/totp/v1\x00" + subject.String() + "\x00" + factor)
}

func (c *MFAFactorCodec) Seal(subject SubjectID, factor, secret string) (string, []byte, error) {
	if c == nil || !validMFAFactorBinding(subject, factor) || len(secret) == 0 || len(secret) > 128 {
		return "", nil, ErrMFAUnavailable
	}
	id := c.keys.ActiveKeyID()
	aead, err := c.aead(id)
	if err != nil {
		return "", nil, err
	}
	plain := []byte(secret)
	defer clear(plain)
	//nolint:gosec // Random-nonce GCM requires nil and generates its own nonce.
	return id, aead.Seal(nil, nil, plain, c.additionalData(subject, factor)), nil
}

// Open returns caller-owned secret bytes; clear them after use.
func (c *MFAFactorCodec) Open(subject SubjectID, factor, keyID string, ciphertext []byte) ([]byte, error) {
	if !validMFAFactorBinding(subject, factor) {
		return nil, ErrMFAUnavailable
	}
	aead, err := c.aead(keyID)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nil, ciphertext, c.additionalData(subject, factor))
	if err != nil {
		return nil, ErrMFAUnavailable
	}
	return plain, nil
}

func (c *MFAFactorCodec) RecoveryDigest(subject SubjectID, factor, code string) ([]byte, error) {
	if c == nil || !validMFADomain(c.domain) || !validMFAFactorBinding(subject, factor) || !IsMFARecoveryCode(code) {
		return nil, ErrMFAUnavailable
	}
	sum := sha256.Sum256([]byte(c.domain + "/recovery/v1\x00" + subject.String() + "\x00" + factor + "\x00" + code))
	return sum[:], nil
}

func IsMFARecoveryCode(code string) bool {
	if len(code) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(code)
	defer clear(raw)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == code
}

func NewMFARecoveryCode() (string, error) {
	raw := make([]byte, 32)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// MFATOTPStep uses six-digit SHA-1 TOTP, thirty-second periods and one-step skew.
// The store must atomically reject step <= the persisted LastStep.
func MFATOTPStep(secret, code string, now time.Time) (int64, bool, error) {
	if len(code) != 6 || now.Unix() < 0 {
		return 0, false, nil
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return 0, false, nil
		}
	}
	for _, offset := range []int64{0, -1, 1} {
		step := now.Unix()/30 + offset
		if step < 0 {
			continue
		}
		valid, err := totp.ValidateCustom(code, secret, time.Unix(step*30, 0), totp.ValidateOpts{
			Period: 30,
			Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false, err
		}
		if valid {
			return step, true, nil
		}
	}
	return 0, false, nil
}

// VerifyMFAFactorLocked only consumes a factor; it is not a login proof. The
// caller validates the subject, session/challenge, binding, revision and expiry,
// and commits factor, challenge, session and audit together before publishing.
func VerifyMFAFactorLocked(ctx context.Context, store MFAFactorStore, codec *MFAFactorCodec,
	subject SubjectID, factor MFAFactorRecord, code string, now time.Time,
) (MFAFactorDecision, error) {
	if store == nil || codec == nil {
		return MFAFactorDenied, ErrMFAUnavailable
	}
	if !factor.Enabled {
		return MFAFactorDenied, nil
	}
	if !validMFAFactorBinding(subject, factor.ID) || factor.Revision < 1 {
		return MFAFactorDenied, ErrMFAUnavailable
	}
	if err := codec.CheckKey(factor.KeyID); err != nil {
		return MFAFactorDenied, err
	}
	admitted, err := store.TakeMFAAttempt(ctx, subject)
	if err != nil {
		return MFAFactorDenied, err
	}
	if !admitted {
		return MFAFactorRateLimited, nil
	}
	return ConsumeMFAFactorLocked(ctx, store, codec, subject, factor, code, now)
}

// ConsumeMFAFactorLocked is for adapters that already charged a durable attempt
// in this same transaction. Never use it without that admission.
func ConsumeMFAFactorLocked(ctx context.Context, store MFAFactorStore, codec *MFAFactorCodec,
	subject SubjectID, factor MFAFactorRecord, code string, now time.Time,
) (MFAFactorDecision, error) {
	if store == nil || codec == nil {
		return MFAFactorDenied, ErrMFAUnavailable
	}
	if !factor.Enabled {
		return MFAFactorDenied, nil
	}
	if !validMFAFactorBinding(subject, factor.ID) || factor.Revision < 1 {
		return MFAFactorDenied, ErrMFAUnavailable
	}
	if err := codec.CheckKey(factor.KeyID); err != nil {
		return MFAFactorDenied, err
	}
	consumed, err := consumeMFAValue(ctx, store, codec, subject, factor, code, now)
	if err != nil {
		return MFAFactorDenied, err
	}
	if !consumed {
		return MFAFactorDenied, nil
	}
	return MFAFactorVerified, nil
}

func consumeMFAValue(
	ctx context.Context, store MFAFactorStore, codec *MFAFactorCodec,
	subject SubjectID, factor MFAFactorRecord, code string, now time.Time,
) (bool, error) {
	if IsMFARecoveryCode(code) {
		digest, err := codec.RecoveryDigest(subject, factor.ID, code)
		if err != nil {
			return false, err
		}
		return store.ConsumeMFARecovery(ctx, subject, factor.ID, factor.Revision, digest)
	}
	plain, err := codec.Open(subject, factor.ID, factor.KeyID, factor.Ciphertext)
	if err != nil {
		return false, err
	}
	defer clear(plain)
	step, valid, err := MFATOTPStep(string(plain), code, now)
	if err != nil {
		return false, ErrMFAUnavailable
	}
	if !valid || step <= factor.LastStep {
		return false, nil
	}
	return store.AdvanceMFAStep(ctx, subject, factor.ID, factor.Revision, factor.LastStep, step)
}
