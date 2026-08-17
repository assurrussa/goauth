package userconfirmationservice

import (
	"context"
	"fmt"

	"github.com/assurrussa/goshared/pkg/logger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/local/confirmation"
	"github.com/assurrussa/goauth/internal/legacy/shared"
)

//go:generate toolsmocks

type userConfirmationRepository interface {
	GetBySubjectID(ctx context.Context, subjectID authcore.SubjectID) ([]confirmation.Record, error)
	IsConfirmed(
		ctx context.Context,
		subjectID authcore.SubjectID,
		confirmationType confirmation.Type,
		purpose confirmation.Purpose,
	) (bool, error)
	GetConfirmationStatus(ctx context.Context, subjectID authcore.SubjectID) (confirmation.Status, error)
}

//go:generate options-gen -out-filename=service_options.gen.go -from-struct=Options
type Options struct {
	logger               logger.Logger              `option:"mandatory" validate:"required"`
	userConfirmationRepo userConfirmationRepository `option:"mandatory" validate:"required"`
}

type Service struct {
	Options
}

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

	return &Service{Options: opts}, nil
}

func (s *Service) GetUserConfirmationStatus(
	ctx context.Context,
	subjectID authcore.SubjectID,
) (*authcore.ConfirmationStatus, error) {
	status, err := s.userConfirmationRepo.GetConfirmationStatus(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get confirmation status: %w", err)
	}

	return &authcore.ConfirmationStatus{
		EmailConfirmed:    status.EmailConfirmed,
		PhoneConfirmed:    status.PhoneConfirmed,
		TelegramConfirmed: status.TelegramConfirmed,
	}, nil
}

func (s *Service) IsUserConfirmed(
	ctx context.Context,
	subjectID authcore.SubjectID,
	confirmationType shared.ConfirmationType,
	purpose shared.ConfirmationPurpose,
) (bool, error) {
	confirmed, err := s.userConfirmationRepo.IsConfirmed(
		ctx,
		subjectID,
		toBaseType(confirmationType),
		toBasePurpose(purpose),
	)
	if err != nil {
		return false, fmt.Errorf("failed to check confirmation: %w", err)
	}

	return confirmed, nil
}

func (s *Service) GetUserConfirmations(
	ctx context.Context,
	subjectID authcore.SubjectID,
) ([]authcore.ConfirmationRecord, error) {
	records, err := s.userConfirmationRepo.GetBySubjectID(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get confirmations: %w", err)
	}

	result := make([]authcore.ConfirmationRecord, 0, len(records))
	for _, record := range records {
		result = append(result, authcore.ConfirmationRecord{
			ID:               record.ID,
			SubjectID:        record.SubjectID,
			ConfirmationType: fromBaseType(record.ConfirmationType),
			ConfirmationInfo: record.ConfirmationInfo,
			Purpose:          fromBasePurpose(record.Purpose),
			ConfirmedAt:      record.ConfirmedAt,
			CreatedAt:        record.CreatedAt,
			UpdatedAt:        record.UpdatedAt,
		})
	}

	return result, nil
}

func toBaseType(value shared.ConfirmationType) confirmation.Type {
	switch value {
	case shared.ConfirmationTypeEmail:
		return confirmation.TypeEmail
	case shared.ConfirmationTypePhone:
		return confirmation.TypePhone
	case shared.ConfirmationTypeTgBot:
		return confirmation.TypeTgBot
	default:
		return confirmation.TypeUnknown
	}
}

func toBasePurpose(value shared.ConfirmationPurpose) confirmation.Purpose {
	switch value {
	case shared.ConfirmationPurposeConfirmation:
		return confirmation.PurposeConfirmation
	default:
		return confirmation.PurposeUnknown
	}
}

func fromBaseType(value confirmation.Type) shared.ConfirmationType {
	switch value {
	case confirmation.TypeEmail:
		return shared.ConfirmationTypeEmail
	case confirmation.TypePhone:
		return shared.ConfirmationTypePhone
	case confirmation.TypeTgBot:
		return shared.ConfirmationTypeTgBot
	default:
		return shared.ConfirmationTypeUnknown
	}
}

func fromBasePurpose(value confirmation.Purpose) shared.ConfirmationPurpose {
	switch value {
	case confirmation.PurposeConfirmation:
		return shared.ConfirmationPurposeConfirmation
	default:
		return shared.ConfirmationPurposeUnknown
	}
}
