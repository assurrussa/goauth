package verifyconfirmationcode

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	logger3 "github.com/assurrussa/goshared/pkg/logger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
	"github.com/assurrussa/goauth/internal/legacy/service/confirmationcodeservice"
	shared "github.com/assurrussa/goauth/internal/legacy/shared"
)

var (
	ErrContactInfoNotFound = errors.New("contact info for confirmation not found")
	ErrInvalidRequest      = errors.New("invalid confirmation request type")
)

//go:generate toolsmocks

type confirmationService interface {
	VerifyCode(
		ctx context.Context,
		subjectID authcore.SubjectID,
		code shared.ConfirmCode,
		codeType shared.ConfirmationType,
		purpose shared.ConfirmationPurpose,
	) error
}

//go:generate options-gen -out-filename=usecase_options.gen.go -from-struct=Options
type Options struct {
	logger              logger3.Logger               `option:"mandatory" validate:"required"`
	confirmationService confirmationService          `option:"mandatory" validate:"required"`
	trx                 outbox.StoragePgsqlTxManager `option:"mandatory" validate:"required"`
}

type UseCase struct {
	Options
}

func Must(opts Options) *UseCase {
	useCase, err := New(opts)
	if err != nil {
		panic(err)
	}
	return useCase
}

func New(opts Options) (*UseCase, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validate options: %w", err)
	}

	return &UseCase{
		Options: opts,
	}, nil
}

func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, fmt.Errorf("validate request: %w", errors.Join(err, ErrInvalidRequest))
	}

	log := u.logger.WithAttrs(
		slog.String("subject_id", req.SubjectID.String()),
		slog.String("code_type", req.CodeType.ToString()),
	)

	normalized := shared.ConfirmCodeNormalize(shared.ConfirmCode(req.Code))

	err := u.trx.RunInTx(ctx, func(ctx context.Context) error {
		return u.confirmationService.VerifyCode(
			ctx, req.SubjectID, normalized, req.CodeType, shared.ConfirmationPurposeConfirmation,
		)
	})
	if err != nil {
		log.ErrorContext(ctx, "failed to verify confirmation code", logger3.Error(err))
		reason := classifyReason(err)
		if reason == "" || reason == "unknown" {
			return Response{}, fmt.Errorf("failed to verify confirmation code: %w", err)
		}

		return Response{Success: false, Reason: reason}, nil
	}

	return Response{
		Success:   true,
		Message:   "Подтверждение успешно пройдено.",
		Confirmed: true,
	}, nil
}

func classifyReason(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, confirmationcodeservice.ErrInvalidCode):
		return "invalid_code"
	case errors.Is(err, confirmationcodeservice.ErrCodeExpired):
		return "expired"
	case errors.Is(err, confirmationcodeservice.ErrAlreadyVerified):
		return "already_verified"
	case errors.Is(err, confirmationcodeservice.ErrMaxAttempts):
		return "max_attempts"
	default:
		return "unknown"
	}
}
