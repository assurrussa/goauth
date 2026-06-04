package confirmation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/assurrussa/goauth/infrastructure/notify"
	notificationsjob "github.com/assurrussa/goauth/infrastructure/notify/notifications"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	confirmationcode "github.com/assurrussa/goauth/internal/confirmationcode"
	"github.com/assurrussa/goauth/shared"
)

var (
	ErrInvalidCodeType = errors.New("invalid code type")
	ErrInvalidPurpose  = errors.New("invalid confirmation purpose")
	ErrCodeNotFound    = errors.New("confirmation code not found")

	ErrRateLimited       = errors.New("rate limited")
	ErrWaitBeforeResend  = errors.New("wait before resend")
	ErrInvalidEmail      = errors.New("invalid email")
	ErrInvalidPhone      = errors.New("invalid phone")
	ErrTelegramNotLinked = errors.New("telegram chat not linked")
	ErrUnsupportedType   = errors.New("unsupported confirmation type")
	ErrInvalidCode       = errors.New("invalid confirmation code")
	ErrCodeExpired       = errors.New("confirmation code expired")
	ErrMaxAttempts       = errors.New("maximum attempts reached")
	ErrAlreadyVerified   = errors.New("code already verified")
)

const (
	defaultCodeExpiration    = time.Hour
	defaultMaxAttempts       = 5
	defaultMinResendInterval = time.Minute
	defaultPerHourLimit      = 5
	defaultPerDayLimit       = 10
)

type Type string

const (
	TypeUnknown Type = ""
	TypeEmail   Type = "email"
	TypePhone   Type = "phone"
	TypeTgBot   Type = "tgbot"
)

type Action int

const (
	ActionSend Action = iota + 1
	ActionVerify
)

type Purpose string

const (
	PurposeUnknown      Purpose = ""
	PurposeConfirmation Purpose = "confirmation"
)

type Code string

func (c Code) String() string {
	return string(c)
}

func NormalizeCode(input string) Code {
	return Code(confirmationcode.Normalize(input))
}

func ParseType(val string) Type {
	switch val {
	case TypeEmail.String():
		return TypeEmail
	case TypePhone.String():
		return TypePhone
	case TypeTgBot.String():
		return TypeTgBot
	default:
		return TypeUnknown
	}
}

func (t Type) String() string {
	return string(t)
}

func (t Type) ValidateFor(action Action) error {
	switch action {
	case ActionSend:
		switch t {
		case TypeEmail, TypeTgBot:
			return nil
		default:
			return fmt.Errorf("invalid %w for send: %s", ErrInvalidCodeType, t)
		}
	case ActionVerify:
		switch t {
		case TypeEmail, TypePhone:
			return nil
		default:
			return fmt.Errorf("invalid %w for verify: %s", ErrInvalidCodeType, t)
		}
	default:
		return fmt.Errorf("invalid action: %d", action)
	}
}

func (t Type) ToRuString() string {
	switch t {
	case TypeEmail:
		return "Email"
	case TypePhone:
		return "Телефон"
	case TypeTgBot:
		return "Telegram"
	default:
		return "Неизвестно"
	}
}

func ParsePurpose(val string) Purpose {
	switch val {
	case PurposeConfirmation.String():
		return PurposeConfirmation
	default:
		return PurposeUnknown
	}
}

func (p Purpose) String() string {
	return string(p)
}

func (p Purpose) Validate() error {
	if p == PurposeConfirmation {
		return nil
	}

	return fmt.Errorf("invalid %w: %s", ErrInvalidPurpose, p)
}

type UsageWindow struct {
	LastHour int
	Last24h  int
}

type CodeRecord struct {
	ID               int64
	SubjectID        shared.SubjectID
	Code             Code
	ConfirmationType Type
	ConfirmationInfo string
	Purpose          Purpose
	Attempts         int
	VerifiedAt       *time.Time
	ExpiresAt        time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Record struct {
	ID               int64
	SubjectID        shared.SubjectID
	ConfirmationType Type
	ConfirmationInfo string
	Purpose          Purpose
	ConfirmedAt      time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Status struct {
	EmailConfirmed    bool `json:"emailConfirmed"`
	PhoneConfirmed    bool `json:"phoneConfirmed"`
	TelegramConfirmed bool `json:"telegramConfirmed"`
}

type CodeRepository interface {
	UpsertCode(ctx context.Context, record CodeRecord) (int64, error)
	//nolint:lll
	GetActiveCodeBySubjectAndType(ctx context.Context, subjectID shared.SubjectID, codeType Type, purpose Purpose) (CodeRecord, error)
	UpdateVerified(ctx context.Context, record CodeRecord) error
	IncrementAttempts(ctx context.Context, id int64) error
	FindLast(ctx context.Context, subjectID shared.SubjectID, targetType Type) (*CodeRecord, error)
	CountSince(ctx context.Context, subjectID shared.SubjectID, targetType Type, since time.Time) (UsageWindow, error)
	CleanupExpiredCodes(ctx context.Context, batchSize, minutes int) (int64, error)
}

type RecordRepository interface {
	Upsert(ctx context.Context, record Record) (int64, error)
	IsConfirmed(ctx context.Context, subjectID shared.SubjectID, confirmationType Type, purpose Purpose) (bool, error)
	GetConfirmationStatus(ctx context.Context, subjectID shared.SubjectID) (Status, error)
	GetBySubjectID(ctx context.Context, subjectID shared.SubjectID) ([]Record, error)
}

type SubjectConfirmationApplier interface {
	ApplyConfirmation(ctx context.Context, subjectID shared.SubjectID, confirmationType Type, confirmedAt time.Time) error
}

type OutboxPutter interface {
	Put(ctx context.Context, name, payload string, availableAt time.Time) (outbox.JobID, error)
}

type Options struct {
	CodeRepo          CodeRepository
	RecordRepo        RecordRepository
	Subjects          SubjectConfirmationApplier
	Outbox            OutboxPutter
	CodeExpiration    time.Duration
	MaxAttempts       int
	MinResendInterval time.Duration
	PerHourLimit      int
	PerDayLimit       int
	Now               func() time.Time
	GenerateCode      func() (Code, error)
}

type Service struct {
	codeRepo          CodeRepository
	recordRepo        RecordRepository
	subjects          SubjectConfirmationApplier
	outbox            OutboxPutter
	codeExpiration    time.Duration
	maxAttempts       int
	minResendInterval time.Duration
	perHourLimit      int
	perDayLimit       int
	now               func() time.Time
	generateCode      func() (Code, error)
}

func New(opts Options) (*Service, error) {
	switch {
	case opts.CodeRepo == nil:
		return nil, errors.New("code repo is required")
	case opts.RecordRepo == nil:
		return nil, errors.New("record repo is required")
	case opts.Subjects == nil:
		return nil, errors.New("subjects applier is required")
	case opts.Outbox == nil:
		return nil, errors.New("outbox is required")
	}

	if opts.CodeExpiration <= 0 {
		opts.CodeExpiration = defaultCodeExpiration
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = defaultMaxAttempts
	}
	if opts.MinResendInterval <= 0 {
		opts.MinResendInterval = defaultMinResendInterval
	}
	if opts.PerHourLimit <= 0 {
		opts.PerHourLimit = defaultPerHourLimit
	}
	if opts.PerDayLimit <= 0 {
		opts.PerDayLimit = defaultPerDayLimit
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.GenerateCode == nil {
		opts.GenerateCode = func() (Code, error) {
			code, err := confirmationcode.Generate()
			return Code(code), err
		}
	}

	return &Service{
		codeRepo:          opts.CodeRepo,
		recordRepo:        opts.RecordRepo,
		subjects:          opts.Subjects,
		outbox:            opts.Outbox,
		codeExpiration:    opts.CodeExpiration,
		maxAttempts:       opts.MaxAttempts,
		minResendInterval: opts.MinResendInterval,
		perHourLimit:      opts.PerHourLimit,
		perDayLimit:       opts.PerDayLimit,
		now:               opts.Now,
		generateCode:      opts.GenerateCode,
	}, nil
}

func Must(opts Options) *Service {
	svc, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("panic: %w", err))
	}

	return svc
}

func (s *Service) GenerateAndSaveCode(
	ctx context.Context,
	subjectID shared.SubjectID,
	codeType Type,
	purpose Purpose,
	info string,
) error {
	if err := codeType.ValidateFor(ActionSend); err != nil {
		return err
	}
	if err := purpose.Validate(); err != nil {
		return err
	}

	code, err := s.generateCode()
	if err != nil {
		return fmt.Errorf("generate code: %w", err)
	}

	payload, err := s.createPayload(codeType, code, info)
	if err != nil {
		return err
	}

	if last, err := s.codeRepo.FindLast(ctx, subjectID, codeType); err == nil && last != nil {
		if s.now().Sub(last.CreatedAt) < s.minResendInterval {
			return ErrWaitBeforeResend
		}
	}

	window, err := s.codeRepo.CountSince(ctx, subjectID, codeType, s.now().Add(-24*time.Hour))
	if err == nil {
		if window.LastHour >= s.perHourLimit || window.Last24h >= s.perDayLimit {
			return ErrRateLimited
		}
	}

	now := s.now()
	record := CodeRecord{
		SubjectID:        subjectID,
		Code:             code,
		ConfirmationType: codeType,
		ConfirmationInfo: info,
		Purpose:          purpose,
		ExpiresAt:        now.Add(s.codeExpiration),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if _, err := s.codeRepo.UpsertCode(ctx, record); err != nil {
		return fmt.Errorf("save confirmation code: %w", err)
	}

	data, err := notificationsjob.MarshalPayload(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	if _, err := s.outbox.Put(ctx, notificationsjob.JobName, data, now); err != nil {
		return fmt.Errorf("outbox put: %w", err)
	}

	return nil
}

func (s *Service) VerifyCode(
	ctx context.Context,
	subjectID shared.SubjectID,
	code Code,
	codeType Type,
	purpose Purpose,
) error {
	if err := codeType.ValidateFor(ActionVerify); err != nil {
		return errors.Join(ErrInvalidCode, err)
	}
	if err := purpose.Validate(); err != nil {
		return errors.Join(ErrInvalidCode, err)
	}

	storedCode, err := s.codeRepo.GetActiveCodeBySubjectAndType(ctx, subjectID, codeType, purpose)
	if err != nil {
		if errors.Is(err, ErrCodeNotFound) {
			return ErrInvalidCode
		}
		return fmt.Errorf("get active confirmation code: %w", err)
	}

	now := s.now()
	switch {
	case storedCode.VerifiedAt != nil && !storedCode.VerifiedAt.IsZero():
		return ErrAlreadyVerified
	case storedCode.Attempts >= s.maxAttempts:
		return ErrMaxAttempts
	case now.After(storedCode.ExpiresAt):
		return ErrCodeExpired
	}

	normalized := NormalizeCode(code.String())
	if storedCode.Code != normalized {
		_ = s.codeRepo.IncrementAttempts(ctx, storedCode.ID)
		return ErrInvalidCode
	}

	storedCode.VerifiedAt = &now
	storedCode.UpdatedAt = now
	if err := s.codeRepo.UpdateVerified(ctx, storedCode); err != nil {
		return fmt.Errorf("mark confirmation code verified: %w", err)
	}

	record := Record{
		SubjectID:        subjectID,
		ConfirmationType: codeType,
		ConfirmationInfo: storedCode.ConfirmationInfo,
		Purpose:          purpose,
		ConfirmedAt:      now,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if _, err := s.recordRepo.Upsert(ctx, record); err != nil {
		return fmt.Errorf("upsert confirmation: %w", err)
	}
	if err := s.subjects.ApplyConfirmation(ctx, subjectID, codeType, now); err != nil {
		return fmt.Errorf("apply confirmation: %w", err)
	}

	return nil
}

func (s *Service) GetConfirmationStatus(ctx context.Context, subjectID shared.SubjectID) (Status, error) {
	return s.recordRepo.GetConfirmationStatus(ctx, subjectID)
}

//nolint:lll
func (s *Service) IsConfirmed(ctx context.Context, subjectID shared.SubjectID, confirmationType Type, purpose Purpose) (bool, error) {
	return s.recordRepo.IsConfirmed(ctx, subjectID, confirmationType, purpose)
}

func (s *Service) GetConfirmations(ctx context.Context, subjectID shared.SubjectID) ([]Record, error) {
	return s.recordRepo.GetBySubjectID(ctx, subjectID)
}

func (s *Service) CleanupExpiredCodes(ctx context.Context, batchSize, minutes int) (int64, error) {
	return s.codeRepo.CleanupExpiredCodes(ctx, batchSize, minutes)
}

func (s *Service) createPayload(codeType Type, code Code, info string) (notificationsjob.Payload, error) {
	switch codeType {
	case TypeEmail:
		if info == "" {
			return notificationsjob.Payload{}, ErrInvalidEmail
		}
		return notificationsjob.Payload{
			Title:    "Код подтверждения",
			To:       info,
			Channel:  notify.ChannelEmail,
			Template: "confirmation_code",
			Metadata: map[string]any{
				"otp":             code.String(),
				"channel":         codeType.ToRuString(),
				"expires_minutes": int(s.codeExpiration.Minutes()),
			},
		}, nil
	case TypeTgBot:
		if info == "" {
			return notificationsjob.Payload{}, ErrTelegramNotLinked
		}
		return notificationsjob.Payload{
			Title:    "Код подтверждения",
			To:       info,
			Channel:  notify.ChannelTelegram,
			Template: "confirmation_code",
			Metadata: map[string]any{
				"otp":             code.String(),
				"channel":         codeType.ToRuString(),
				"expires_minutes": int(s.codeExpiration.Minutes()),
			},
		}, nil
	default:
		return notificationsjob.Payload{}, ErrUnsupportedType
	}
}
