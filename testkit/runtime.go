package testkit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/assurrussa/goauth"
)

type EventSink struct {
	mu     sync.Mutex
	events []goauth.EncryptedEvent
}

func (s *EventSink) EnqueueEncrypted(ctx context.Context, event goauth.EncryptedEvent) error {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, cloneEvent(event))

	return nil
}

func (s *EventSink) Events() []goauth.EncryptedEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]goauth.EncryptedEvent, 0, len(s.events))
	for _, event := range s.events {
		result = append(result, cloneEvent(event))
	}

	return result
}

func (s *EventSink) DeleteEncrypted(ctx context.Context, eventID string) error {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	for index, event := range s.events {
		if event.ID != eventID {
			continue
		}
		for cipherIndex := range s.events[index].Envelope.Ciphertext {
			s.events[index].Envelope.Ciphertext[cipherIndex] = 0
		}
		s.events = append(s.events[:index], s.events[index+1:]...)
		return nil
	}

	return nil
}

func (s *EventSink) DeleteExpiredEncrypted(ctx context.Context, before time.Time) (int64, error) {
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.events[:0]
	var deleted int64
	for index := range s.events {
		if s.events[index].Envelope.DeleteAfter.After(before) {
			kept = append(kept, s.events[index])
			continue
		}
		for cipherIndex := range s.events[index].Envelope.Ciphertext {
			s.events[index].Envelope.Ciphertext[cipherIndex] = 0
		}
		deleted++
	}
	s.events = kept

	return deleted, nil
}

type Fixture struct {
	Runtime      *goauth.Runtime
	Store        *Store
	Events       *EventSink
	SigningKeys  goauth.KeyRing
	TokenKeys    goauth.KeyRing
	EnvelopeKeys goauth.KeyRing
}

type RuntimeOption func(*goauth.Config)

func NewRuntime(options ...RuntimeOption) (*Fixture, error) {
	signingKeys, err := goauth.NewKeyRing("jwt-v1", goauth.Key{ID: "jwt-v1", Material: bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		return nil, err
	}
	tokenKeys, err := goauth.NewKeyRing("token-v1", goauth.Key{ID: "token-v1", Material: bytes.Repeat([]byte{2}, 32)})
	if err != nil {
		return nil, err
	}
	envelopeKeys, err := goauth.NewKeyRing("outbox-v1", goauth.Key{ID: "outbox-v1", Material: bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		return nil, err
	}
	store := NewStore()
	events := &EventSink{}
	config := goauth.Config{
		Store:           store,
		AuthTransaction: &fixtureTransaction{store: store, events: events},
		AuditSink:       store,
		Signing:         goauth.SigningConfig{Issuer: "https://auth.example.test", Audience: "test", Keys: signingKeys},
		TokenHMACKeys:   tokenKeys,
		OutboxAEADKeys:  envelopeKeys,
		EventSink:       events,
		URLBuilder: goauth.URLBuilderFunc(func(_ context.Context, token string) (string, error) {
			return "https://app.example.test/reset-password?token=" + url.QueryEscape(token), nil
		}),
		MembershipGate: goauth.MembershipGateFunc(func(context.Context, goauth.Realm, goauth.Account) error {
			return nil
		}),
		ResetResponseFloor: time.Nanosecond,
	}
	for _, option := range options {
		option(&config)
	}
	runtime, err := goauth.NewRuntime(config)
	if err != nil {
		return nil, err
	}

	return &Fixture{
		Runtime:      runtime,
		Store:        store,
		Events:       events,
		SigningKeys:  signingKeys,
		TokenKeys:    tokenKeys,
		EnvelopeKeys: envelopeKeys,
	}, nil
}

func DecryptNotification(keys goauth.KeyRing, envelope goauth.EncryptedEnvelope) (goauth.Notification, error) {
	key, err := keys.Get(envelope.KeyID)
	if err != nil {
		return goauth.Notification{}, err
	}
	block, err := aes.NewCipher(key.Material)
	if err != nil {
		return goauth.Notification{}, fmt.Errorf("create test envelope cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return goauth.Notification{}, fmt.Errorf("create test envelope GCM: %w", err)
	}
	if len(envelope.Nonce) != gcm.NonceSize() {
		return goauth.Notification{}, errors.New("invalid test envelope nonce")
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, envelope.AdditionalData)
	if err != nil {
		return goauth.Notification{}, errors.New("decrypt test notification")
	}
	var notification goauth.Notification
	if err := json.Unmarshal(plaintext, &notification); err != nil {
		return goauth.Notification{}, fmt.Errorf("decode test notification: %w", err)
	}

	return notification, nil
}

func cloneEvent(event goauth.EncryptedEvent) goauth.EncryptedEvent {
	clone := event
	clone.Envelope.Nonce = append([]byte(nil), event.Envelope.Nonce...)
	clone.Envelope.Ciphertext = append([]byte(nil), event.Envelope.Ciphertext...)
	clone.Envelope.AdditionalData = append([]byte(nil), event.Envelope.AdditionalData...)

	return clone
}

var _ goauth.EncryptedEventSink = (*EventSink)(nil)
