package goauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"
)

const symmetricKeySize = 32

type Key struct {
	ID       string
	Material []byte
}

// KeyRing is an immutable versioned set of 256-bit symmetric keys.
type KeyRing struct {
	active string
	keys   map[string][]byte
}

func NewKeyRing(activeKeyID string, keys ...Key) (KeyRing, error) {
	activeKeyID = strings.TrimSpace(activeKeyID)
	if activeKeyID == "" || strings.Contains(activeKeyID, ".") {
		return KeyRing{}, fmt.Errorf("%w: invalid active key id", ErrKeyRingInvalid)
	}

	values := make(map[string][]byte, len(keys))
	for _, key := range keys {
		keyID := strings.TrimSpace(key.ID)
		if keyID == "" || strings.Contains(keyID, ".") {
			return KeyRing{}, fmt.Errorf("%w: invalid key id", ErrKeyRingInvalid)
		}
		if len(key.Material) != symmetricKeySize {
			return KeyRing{}, fmt.Errorf("%w: key %q must contain %d bytes", ErrKeyRingInvalid, keyID, symmetricKeySize)
		}
		if _, exists := values[keyID]; exists {
			return KeyRing{}, fmt.Errorf("%w: duplicate key id %q", ErrKeyRingInvalid, keyID)
		}

		values[keyID] = slices.Clone(key.Material)
	}

	if _, ok := values[activeKeyID]; !ok {
		return KeyRing{}, fmt.Errorf("%w: active key %q is missing", ErrKeyRingInvalid, activeKeyID)
	}

	return KeyRing{active: activeKeyID, keys: values}, nil
}

func (r KeyRing) ActiveKeyID() string {
	return r.active
}

func (r KeyRing) Active() (Key, error) {
	return r.Get(r.active)
}

func (r KeyRing) Get(keyID string) (Key, error) {
	material, ok := r.keys[strings.TrimSpace(keyID)]
	if !ok {
		return Key{}, fmt.Errorf("%w: unknown key %q", ErrKeyRingInvalid, keyID)
	}

	return Key{ID: strings.TrimSpace(keyID), Material: slices.Clone(material)}, nil
}

func (r KeyRing) IDs() []string {
	ids := make([]string, 0, len(r.keys))
	for id := range r.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	return ids
}

func validateDistinctKeyRings(rings ...KeyRing) error {
	seen := make(map[[sha256.Size]byte]string)
	for ringIndex, ring := range rings {
		if _, err := ring.Active(); err != nil {
			return err
		}
		for _, id := range ring.IDs() {
			key, err := ring.Get(id)
			if err != nil {
				return err
			}
			fingerprint := sha256.Sum256(key.Material)
			if previous, exists := seen[fingerprint]; exists {
				return fmt.Errorf("%w: ring %d key %q matches %s", ErrKeyPurposeCollision, ringIndex, id, previous)
			}
			seen[fingerprint] = fmt.Sprintf("ring %d key %q", ringIndex, id)
		}
	}

	return nil
}

type opaqueToken struct {
	raw      string
	keyID    string
	selector string
	secret   []byte
}

type secretCodec struct {
	keys   KeyRing
	random io.Reader
}

func newSecretCodec(keys KeyRing, random io.Reader) *secretCodec {
	return &secretCodec{keys: keys, random: random}
}

func (c *secretCodec) Generate(purpose string) (opaqueToken, SecretDigest, error) {
	selectorBytes := make([]byte, 16)
	if _, err := io.ReadFull(c.random, selectorBytes); err != nil {
		return opaqueToken{}, SecretDigest{}, fmt.Errorf("generate token selector: %w", err)
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(c.random, secret); err != nil {
		return opaqueToken{}, SecretDigest{}, fmt.Errorf("generate token secret: %w", err)
	}

	key, err := c.keys.Active()
	if err != nil {
		return opaqueToken{}, SecretDigest{}, err
	}
	selector := base64.RawURLEncoding.EncodeToString(selectorBytes)
	raw := strings.Join([]string{key.ID, selector, base64.RawURLEncoding.EncodeToString(secret)}, ".")
	token := opaqueToken{raw: raw, keyID: key.ID, selector: selector, secret: secret}

	return token, digestSecret(key, purpose, selector, secret), nil
}

func (c *secretCodec) Parse(raw, purpose string) (opaqueToken, SecretDigest, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return opaqueToken{}, SecretDigest{}, ErrInvalidToken
	}

	selectorBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(selectorBytes) != 16 {
		return opaqueToken{}, SecretDigest{}, ErrInvalidToken
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 {
		return opaqueToken{}, SecretDigest{}, ErrInvalidToken
	}
	key, err := c.keys.Get(parts[0])
	if err != nil {
		return opaqueToken{}, SecretDigest{}, ErrInvalidToken
	}

	token := opaqueToken{raw: raw, keyID: key.ID, selector: parts[1], secret: secret}
	return token, digestSecret(key, purpose, parts[1], secret), nil
}

func (c *secretCodec) DigestAll(purpose, value string) ([]SecretDigest, error) {
	if value == "" {
		return nil, ErrInvalidConfirmationCode
	}

	digests := make([]SecretDigest, 0, len(c.keys.keys))
	for _, keyID := range c.keys.IDs() {
		key, err := c.keys.Get(keyID)
		if err != nil {
			return nil, err
		}
		digests = append(digests, digestSecret(key, purpose, "", []byte(value)))
	}

	return digests, nil
}

func (c *secretCodec) DigestActive(purpose, value string) (SecretDigest, error) {
	key, err := c.keys.Active()
	if err != nil {
		return SecretDigest{}, err
	}

	return digestSecret(key, purpose, "", []byte(value)), nil
}

func digestSecret(key Key, purpose, selector string, secret []byte) SecretDigest {
	mac := hmac.New(sha256.New, key.Material)
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(selector))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(secret)

	return SecretDigest{KeyID: key.ID, Digest: mac.Sum(nil)}
}

type envelopeCipher struct {
	keys   KeyRing
	random io.Reader
	now    func() time.Time
}

func newEnvelopeCipher(keys KeyRing, random io.Reader, now func() time.Time) *envelopeCipher {
	return &envelopeCipher{keys: keys, random: random, now: now}
}

func (c *envelopeCipher) Encrypt(plaintext, additionalData []byte, retention time.Duration) (EncryptedEnvelope, error) {
	key, err := c.keys.Active()
	if err != nil {
		return EncryptedEnvelope{}, err
	}
	block, err := aes.NewCipher(key.Material)
	if err != nil {
		return EncryptedEnvelope{}, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedEnvelope{}, fmt.Errorf("create AES-GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return EncryptedEnvelope{}, fmt.Errorf("generate envelope nonce: %w", err)
	}

	now := c.now().UTC()
	return EncryptedEnvelope{
		KeyID:          key.ID,
		Nonce:          nonce,
		Ciphertext:     gcm.Seal(nil, nonce, plaintext, additionalData),
		AdditionalData: slices.Clone(additionalData),
		CreatedAt:      now,
		DeleteAfter:    now.Add(retention),
	}, nil
}

func (c *envelopeCipher) Decrypt(envelope EncryptedEnvelope) ([]byte, error) {
	key, err := c.keys.Get(envelope.KeyID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key.Material)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	if len(envelope.Nonce) != gcm.NonceSize() || len(envelope.Ciphertext) < gcm.Overhead() {
		return nil, errors.New("invalid encrypted envelope")
	}

	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, envelope.AdditionalData)
	if err != nil {
		return nil, errors.New("invalid encrypted envelope")
	}

	return bytes.Clone(plaintext), nil
}
