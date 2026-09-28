package goauth

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	passwordResetSecretPurpose = "password-reset"
	emailChallengeSecretPrefix = "email-challenge:"
	notificationExpiresKey     = "expires"
)

type jsonNotificationRenderer struct{}

func (jsonNotificationRenderer) RenderNotification(_ context.Context, notification Notification) ([]byte, error) {
	return json.Marshal(notification)
}

func (r *Runtime) RequestPasswordReset(ctx context.Context, email string) error {
	startedAt := time.Now()
	defer r.waitForResetResponseFloor(startedAt)

	normalized, err := r.normalizeIdentifier(ctx, IdentifierInput{Scheme: IdentifierSchemeEmail, Value: email})
	if err != nil {
		return nil
	}
	allowed, err := r.takeIdentifierRateLimit(ctx, "password_reset", normalized, r.passwordResetRateLimit)
	if err != nil {
		return fmt.Errorf("check password reset rate limit: %w", err)
	}
	if !allowed {
		return nil
	}
	record, err := r.store.FindLocalAccount(ctx, normalized)
	if err != nil {
		if errors.Is(err, ErrAccountNotFound) {
			return nil
		}
		return fmt.Errorf("lookup password reset account: %w", err)
	}
	if record.Account.IsZero() || record.Account.Subject.Status != SubjectStatusActive {
		return nil
	}
	token, digest, err := r.secretCodec.Generate(passwordResetSecretPurpose)
	if err != nil {
		return err
	}
	now := r.now().UTC()
	resetURL, err := r.urlBuilder.PasswordResetURL(ctx, token.raw)
	if err != nil {
		return fmt.Errorf("build password reset URL: %w", err)
	}
	if err := validatePasswordResetURL(resetURL); err != nil {
		return err
	}
	return r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		if err := r.store.CreatePasswordReset(txCtx, PasswordResetRecord{
			SubjectID:               record.Account.Subject.ID,
			Selector:                token.selector,
			Digest:                  digest,
			ExpectedNormalizedEmail: record.Account.PrimaryEmail.NormalizedValue,
			ExpectedSecurityVersion: record.Account.Subject.SecurityVersion,
			ExpiresAt:               now.Add(r.passwordResetTTL),
			CreatedAt:               now,
		}); err != nil {
			if errors.Is(err, ErrAccountNotFound) {
				return nil
			}
			return fmt.Errorf("create password reset: %w", err)
		}
		if err := r.enqueueNotification(txCtx, "password_reset", record.Account, Notification{
			Template: "password_reset",
			To:       record.Account.PrimaryEmail.DisplayValue,
			Data: map[string]string{
				"reset_url":            resetURL,
				notificationExpiresKey: r.passwordResetTTL.String(),
			},
		}, notificationMetadata{referenceID: token.selector, validUntil: now.Add(r.passwordResetTTL)}); err != nil {
			return err
		}
		return r.recordAudit(txCtx, SecurityEvent{
			Type:      SecurityEventPasswordResetIssued,
			SubjectID: record.Account.Subject.ID,
			At:        now,
		})
	})
}

func (r *Runtime) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	if err := r.passwordPolicy.Validate(newPassword); err != nil {
		return err
	}
	token, digest, err := r.secretCodec.Parse(strings.TrimSpace(rawToken), passwordResetSecretPurpose)
	if err != nil {
		return ErrInvalidToken
	}
	passwordPHC, err := r.hasher.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash replacement password: %w", err)
	}
	now := r.now().UTC()
	var outcomeErr error
	err = r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		result, err := r.store.ConsumePasswordReset(txCtx, PasswordResetConsumeRequest{
			Selector:    token.selector,
			Digest:      digest,
			PasswordPHC: passwordPHC,
			Now:         now,
		})
		if err != nil {
			return fmt.Errorf("consume password reset: %w", err)
		}
		switch result.Status {
		case PasswordResetConsumed:
		case PasswordResetExpired:
			outcomeErr = ErrExpiredToken
			return nil
		case PasswordResetUsed:
			outcomeErr = ErrResetAlreadyUsed
			return nil
		default:
			outcomeErr = ErrInvalidToken
			return nil
		}
		if err := r.enqueueNotification(txCtx, "password_reset_success", result.Account, Notification{
			Template: "password_reset_success",
			To:       result.Account.PrimaryEmail.DisplayValue,
		}); err != nil {
			return err
		}
		return r.recordAudit(txCtx, SecurityEvent{
			Type:      SecurityEventPasswordResetUsed,
			SubjectID: result.Account.Subject.ID,
			At:        now,
		})
	})
	if err != nil {
		return err
	}
	return outcomeErr
}

func (r *Runtime) SendEmailChallenge(
	ctx context.Context,
	subjectID SubjectID,
	purpose EmailChallengePurpose,
) error {
	if subjectID.IsZero() {
		return ErrAccountNotFound
	}
	if err := purpose.Validate(); err != nil {
		return err
	}
	account, err := r.store.GetAccount(ctx, subjectID)
	if err != nil {
		return fmt.Errorf("get challenge account: %w", err)
	}
	if account.Subject.Status != SubjectStatusActive {
		return ErrAccountUnavailable
	}
	if account.PrimaryEmail.Scheme != IdentifierSchemeEmail || account.PrimaryEmail.ID == "" {
		return ErrInvalidIdentifier
	}
	code, err := r.generateEmailCode()
	if err != nil {
		return err
	}
	digest, err := r.secretCodec.DigestActive(emailChallengeSecretPrefix+string(purpose), code)
	if err != nil {
		return err
	}
	rateDigest, err := r.secretCodec.DigestActive("rate-limit:email-challenge", subjectID.String())
	if err != nil {
		return err
	}
	now := r.now().UTC()
	challengeID := uuid.NewString()
	var outcomeErr error
	err = r.inNotificationTransaction(ctx, func(txCtx context.Context) error {
		issue, err := r.store.IssueEmailChallenge(txCtx, EmailChallengeRecord{
			ID:                      challengeID,
			SubjectID:               subjectID,
			IdentifierID:            account.PrimaryEmail.ID,
			ExpectedNormalizedEmail: account.PrimaryEmail.NormalizedValue,
			ExpectedSecurityVersion: account.Subject.SecurityVersion,
			Purpose:                 purpose,
			Digest:                  digest,
			RateDigest:              rateDigest,
			MaxAttempts:             5,
			ExpiresAt:               now.Add(r.challengeTTL),
			CreatedAt:               now,
		}, EmailChallengeLimits{
			MinResendInterval: time.Minute,
			PerHour:           5,
			PerDay:            10,
		})
		if err != nil {
			return fmt.Errorf("issue email challenge: %w", err)
		}
		switch issue.Status {
		case EmailChallengeIssued:
		case EmailChallengeWait:
			outcomeErr = ErrConfirmationResendDelay
			return nil
		default:
			outcomeErr = ErrConfirmationRateLimited
			return nil
		}
		if err := r.enqueueNotification(txCtx, "email_challenge", account, Notification{
			Template: "email_challenge",
			To:       account.PrimaryEmail.DisplayValue,
			Data: map[string]string{
				"code":                 code,
				notificationExpiresKey: r.challengeTTL.String(),
			},
		}, notificationMetadata{referenceID: challengeID, validUntil: now.Add(r.challengeTTL)}); err != nil {
			return err
		}
		return r.recordAudit(txCtx, SecurityEvent{
			Type:      SecurityEventEmailChallengeIssued,
			SubjectID: subjectID,
			At:        now,
		})
	})
	if err != nil {
		return err
	}
	return outcomeErr
}

type RateLimitPolicy struct {
	Window time.Duration
	Limit  int
}

func (p RateLimitPolicy) Validate() error {
	if p.Window < time.Second || p.Window > 24*time.Hour || p.Limit <= 0 || p.Limit > 10_000 {
		return errors.New("invalid rate limit policy")
	}

	return nil
}

func (r *Runtime) takeIdentifierRateLimit(
	ctx context.Context,
	action string,
	identifier IdentifierInput,
	policy RateLimitPolicy,
) (bool, error) {
	digest, err := r.secretCodec.DigestActive(
		"rate-limit:"+action,
		string(identifier.Scheme)+":"+identifier.Value,
	)
	if err != nil {
		return false, err
	}
	result, err := r.store.TakeRateLimit(ctx, RateLimitRequest{
		Action: action,
		Bucket: digest,
		Window: policy.Window,
		Limit:  policy.Limit,
		Now:    r.now().UTC(),
	})
	if err != nil {
		return false, err
	}

	return result.Allowed, nil
}

func (r *Runtime) VerifyEmailChallenge(
	ctx context.Context,
	subjectID SubjectID,
	purpose EmailChallengePurpose,
	code string,
) (Account, error) {
	if subjectID.IsZero() {
		return Account{}, ErrInvalidConfirmationCode
	}
	if err := purpose.Validate(); err != nil {
		return Account{}, ErrInvalidConfirmationCode
	}
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return Account{}, ErrInvalidConfirmationCode
	}
	for _, ch := range code {
		if ch < '0' || ch > '9' {
			return Account{}, ErrInvalidConfirmationCode
		}
	}
	digests, err := r.secretCodec.DigestAll(emailChallengeSecretPrefix+string(purpose), code)
	if err != nil {
		return Account{}, err
	}
	now := r.now().UTC()
	result, err := r.store.VerifyEmailChallenge(ctx, EmailChallengeVerifyRequest{
		SubjectID: subjectID,
		Purpose:   purpose,
		Digests:   digests,
		Now:       now,
	})
	if err != nil {
		return Account{}, fmt.Errorf("verify email challenge: %w", err)
	}
	switch result.Status {
	case EmailChallengeVerified:
	case EmailChallengeInvalid:
		return Account{}, ErrInvalidConfirmationCode
	case EmailChallengeExpired:
		return Account{}, ErrConfirmationExpired
	case EmailChallengeAttemptsUsed:
		return Account{}, ErrConfirmationAttempts
	case EmailChallengeAlreadyVerified:
		return result.Account, nil
	default:
		return Account{}, ErrInvalidConfirmationCode
	}
	if err := r.recordAudit(ctx, SecurityEvent{
		Type:      SecurityEventEmailVerified,
		SubjectID: subjectID,
		At:        now,
	}); err != nil {
		return Account{}, err
	}

	return result.Account, nil
}

func (r *Runtime) generateEmailCode() (string, error) {
	value, err := cryptorand.Int(r.random, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("generate email confirmation code: %w", err)
	}

	return fmt.Sprintf("%06d", value.Int64()), nil
}

func (r *Runtime) enqueueNotification(
	ctx context.Context,
	eventType string,
	account Account,
	notification Notification,
	metadata ...notificationMetadata,
) error {
	var (
		payload []byte
		err     error
	)
	if r.managedNotificationDelivery {
		payload, err = json.Marshal(notification)
	} else {
		payload, err = r.renderer.RenderNotification(ctx, notification)
	}
	if err != nil {
		return fmt.Errorf("render encrypted notification: %w", err)
	}
	for key, value := range notification.Data {
		delete(notification.Data, key)
		_ = value
	}
	event := EncryptedEvent{
		ID:        uuid.NewString(),
		Type:      eventType,
		SubjectID: account.Subject.ID,
	}
	if r.managedNotificationDelivery {
		event.ValidUntil = r.now().UTC().Add(r.envelopeRetention)
		if len(metadata) > 0 {
			event.ReferenceID = metadata[0].referenceID
			if !metadata[0].validUntil.IsZero() && metadata[0].validUntil.Before(event.ValidUntil) {
				event.ValidUntil = metadata[0].validUntil.UTC()
			}
		}
		// PostgreSQL timestamps have microsecond precision. Bind the value
		// that will actually round-trip from the durable queue to the AEAD.
		event.ValidUntil = event.ValidUntil.Truncate(time.Microsecond)
	}
	additionalData := notificationAdditionalData(event)
	envelope, err := r.envelopes.Encrypt(payload, additionalData, r.envelopeRetention)
	for index := range payload {
		payload[index] = 0
	}
	if err != nil {
		return fmt.Errorf("encrypt notification: %w", err)
	}
	event.Envelope = envelope
	if err := r.eventSink.EnqueueEncrypted(ctx, event); err != nil {
		return fmt.Errorf("enqueue encrypted notification: %w", err)
	}

	return nil
}

func (r *Runtime) AcknowledgeEncryptedEvent(ctx context.Context, eventID string) error {
	if r.managedNotificationDelivery {
		return errors.New("managed notifications can only be acknowledged by the lease-owning worker")
	}
	eventID = strings.TrimSpace(eventID)
	if eventID == "" {
		return errors.New("encrypted event ID is required")
	}
	if err := r.eventSink.DeleteEncrypted(ctx, eventID); err != nil {
		return fmt.Errorf("delete delivered encrypted event: %w", err)
	}

	return nil
}

func (r *Runtime) DecryptNotificationEvent(event EncryptedEvent) (Notification, error) {
	expectedAdditionalData := notificationAdditionalData(event)
	if event.ID == "" || event.Type == "" || event.SubjectID.IsZero() ||
		!bytes.Equal(event.Envelope.AdditionalData, expectedAdditionalData) {
		return Notification{}, errors.New("invalid encrypted notification event")
	}
	plaintext, err := r.envelopes.Decrypt(event.Envelope)
	if err != nil {
		return Notification{}, err
	}
	defer func() {
		for index := range plaintext {
			plaintext[index] = 0
		}
	}()
	var notification Notification
	if err := json.Unmarshal(plaintext, &notification); err != nil {
		return Notification{}, errors.New("invalid encrypted notification payload")
	}
	if strings.TrimSpace(notification.Template) == "" || strings.TrimSpace(notification.To) == "" {
		return Notification{}, errors.New("invalid encrypted notification payload")
	}

	return notification, nil
}

func notificationAdditionalData(event EncryptedEvent) []byte {
	if event.ValidUntil.IsZero() {
		return []byte(event.Type + ":" + event.SubjectID.String())
	}
	return []byte("goauth-notification:v1:" +
		strconv.Quote(event.ID) + ":" + strconv.Quote(event.Type) + ":" +
		strconv.Quote(event.SubjectID.String()) + ":" + strconv.Quote(event.ReferenceID) + ":" +
		strconv.FormatInt(event.ValidUntil.UTC().UnixMicro(), 10))
}

func (r *Runtime) CleanupExpiredEncryptedEvents(ctx context.Context) (int64, error) {
	deleted, err := r.eventSink.DeleteExpiredEncrypted(ctx, r.now().UTC())
	if err != nil {
		return 0, fmt.Errorf("delete expired encrypted events: %w", err)
	}

	return deleted, nil
}

func (r *Runtime) waitForResetResponseFloor(startedAt time.Time) {
	remaining := r.resetResponseFloor - time.Since(startedAt)
	if remaining > 0 {
		time.Sleep(remaining)
	}
}

func validatePasswordResetURL(value string) error {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(value))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("password reset URL must be absolute")
	}
	isLocalHTTP := parsed.Scheme == "http" &&
		(parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")
	if parsed.Scheme != "https" && !isLocalHTTP {
		return errors.New("password reset URL must use HTTPS")
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.Query().Get("email") != "" {
		return errors.New("password reset URL contains forbidden components")
	}

	return nil
}
