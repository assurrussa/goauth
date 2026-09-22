package confirmationcodeservice

import (
	"context"
	"fmt"
	"time"

	logger3 "github.com/assurrussa/gologger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/infrastructure/notify"
	base "github.com/assurrussa/goauth/internal/legacy/local/confirmation"
	"github.com/assurrussa/goauth/internal/legacy/shared"
)

//go:generate toolsmocks

type UsageWindow = base.UsageWindow

type userConfirmationCodeRepository interface {
	base.CodeRepository
}

type userConfirmationRepository interface {
	base.RecordRepository
}

type notificationService interface {
	SendToChannel(
		ctx context.Context,
		channel notify.NotificationChannel,
		notification *notify.Notification,
		recipients ...*notify.Recipient,
	) ([]*notify.NotificationResult, error)
}

type outboxPutter = base.OutboxPutter

type SubjectConfirmationStore interface {
	MarkEmailConfirmed(ctx context.Context, subjectID authcore.SubjectID, confirmedAt time.Time) error
}

type confirmationSubjectApplier struct {
	subjects    SubjectConfirmationStore
	projections authcore.ProfileProjectionWriter
}

func (a confirmationSubjectApplier) ApplyConfirmation(
	ctx context.Context,
	subjectID authcore.SubjectID,
	confirmationType base.Type,
	confirmedAt time.Time,
) error {
	switch confirmationType {
	case base.TypeEmail:
		return a.subjects.MarkEmailConfirmed(ctx, subjectID, confirmedAt)
	case base.TypePhone:
		return a.projections.MarkPhoneConfirmed(ctx, subjectID, confirmedAt)
	default:
		return nil
	}
}

//go:generate options-gen -out-filename=service_options.gen.go -from-struct=Options
type Options struct {
	notificationService      notificationService              `option:"mandatory" validate:"required"`
	userConfirmationCodeRepo userConfirmationCodeRepository   `option:"mandatory" validate:"required"`
	profiles                 authcore.ProfileLookup           `option:"mandatory" validate:"required"`
	projections              authcore.ProfileProjectionWriter `option:"mandatory" validate:"required"`
	subjects                 SubjectConfirmationStore         `option:"mandatory" validate:"required"`
	userConfirmationRepo     userConfirmationRepository       `option:"mandatory" validate:"required"`
	logger                   logger3.Logger                   `option:"mandatory" validate:"required"`
	codeExpiration           time.Duration                    `default:"60m"`
	maxAttempts              int                              `default:"5"`
	minResendInterval        time.Duration                    `default:"60s"`
	telegramBotURL           string                           `default:""`
	perHourLimit             int                              `default:"5"`
	perDayLimit              int                              `default:"10"`
	outbox                   outboxPutter                     `option:"mandatory" validate:"required"`
}

type Service struct {
	profiles authcore.ProfileLookup
	base     *base.Service
}

var (
	ErrRateLimited       = base.ErrRateLimited
	ErrWaitBeforeResend  = base.ErrWaitBeforeResend
	ErrInvalidEmail      = base.ErrInvalidEmail
	ErrInvalidPhone      = base.ErrInvalidPhone
	ErrTelegramNotLinked = base.ErrTelegramNotLinked
	ErrUnsupportedType   = base.ErrUnsupportedType
	ErrInvalidCode       = base.ErrInvalidCode
	ErrCodeExpired       = base.ErrCodeExpired
	ErrMaxAttempts       = base.ErrMaxAttempts
	ErrAlreadyVerified   = base.ErrAlreadyVerified
)

func Must(opts Options) *Service {
	service, err := New(opts)
	if err != nil {
		panic(err)
	}

	return service
}

func New(opts Options) (*Service, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validate options: %w", err)
	}

	baseSvc, err := base.New(base.Options{
		CodeRepo:   opts.userConfirmationCodeRepo,
		RecordRepo: opts.userConfirmationRepo,
		Subjects: confirmationSubjectApplier{
			subjects:    opts.subjects,
			projections: opts.projections,
		},
		Outbox:            opts.outbox,
		CodeExpiration:    opts.codeExpiration,
		MaxAttempts:       opts.maxAttempts,
		MinResendInterval: opts.minResendInterval,
		PerHourLimit:      opts.perHourLimit,
		PerDayLimit:       opts.perDayLimit,
	})
	if err != nil {
		return nil, fmt.Errorf("build goauth confirmation service: %w", err)
	}

	return &Service{
		profiles: opts.profiles,
		base:     baseSvc,
	}, nil
}

func (s *Service) GenerateAndSaveCode(
	ctx context.Context,
	subjectID authcore.SubjectID,
	codeType shared.ConfirmationType,
	purpose shared.ConfirmationPurpose,
	info string,
) error {
	return s.base.GenerateAndSaveCode(ctx, subjectID, toBaseType(codeType), toBasePurpose(purpose), info)
}

func (s *Service) VerifyCode(
	ctx context.Context,
	subjectID authcore.SubjectID,
	code shared.ConfirmCode,
	codeType shared.ConfirmationType,
	purpose shared.ConfirmationPurpose,
) error {
	return s.base.VerifyCode(
		ctx,
		subjectID,
		base.Code(shared.ConfirmCodeNormalize(code).String()),
		toBaseType(codeType),
		toBasePurpose(purpose),
	)
}

func (s *Service) GetConfirmationInfo(
	ctx context.Context,
	subjectID authcore.SubjectID,
) (authcore.ConfirmationInfo, error) {
	status, err := s.base.GetConfirmationStatus(ctx, subjectID)
	if err != nil {
		return authcore.ConfirmationInfo{}, fmt.Errorf("confirmationcodeservice.GetConfirmationInfo: %w", err)
	}

	profile, err := s.profiles.GetBySubjectID(ctx, subjectID)
	if err != nil {
		return authcore.ConfirmationInfo{}, fmt.Errorf("confirmationcodeservice.GetConfirmationInfo: %w", err)
	}

	return authcore.ConfirmationInfo{
		Profile: profile,
		Status: authcore.ConfirmationStatus{
			EmailConfirmed:    status.EmailConfirmed,
			PhoneConfirmed:    status.PhoneConfirmed,
			TelegramConfirmed: status.TelegramConfirmed,
		},
	}, nil
}

func (s *Service) CleanupExpiredCodes(ctx context.Context, batchSize, minutes int) (int64, error) {
	return s.base.CleanupExpiredCodes(ctx, batchSize, minutes)
}

func toBaseType(codeType shared.ConfirmationType) base.Type {
	switch codeType {
	case shared.ConfirmationTypeEmail:
		return base.TypeEmail
	case shared.ConfirmationTypePhone:
		return base.TypePhone
	case shared.ConfirmationTypeTgBot:
		return base.TypeTgBot
	default:
		return base.TypeUnknown
	}
}

func toBasePurpose(purpose shared.ConfirmationPurpose) base.Purpose {
	switch purpose {
	case shared.ConfirmationPurposeConfirmation:
		return base.PurposeConfirmation
	default:
		return base.PurposeUnknown
	}
}
