package sendconfirmationcode

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	logger3 "github.com/assurrussa/goshared/pkg/logger"

	authcore "github.com/assurrussa/goauth/core"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/service/confirmationcodeservice"
	shared2 "github.com/assurrussa/goauth/shared"
)

//go:generate toolsmocks

type confirmationService interface {
	GenerateAndSaveCode(
		ctx context.Context,
		subjectID authcore.SubjectID,
		codeType shared2.ConfirmationType,
		purpose shared2.ConfirmationPurpose,
		targetConfirm string,
	) error
}

type profileLookup interface {
	GetBySubjectID(ctx context.Context, subjectID authcore.SubjectID) (authcore.Profile, error)
}

//go:generate options-gen -out-filename=usecase_options.gen.go -from-struct=Options
type Options struct {
	logger              logger3.Logger               `option:"mandatory" validate:"required"`
	confirmationService confirmationService          `option:"mandatory" validate:"required"`
	profiles            profileLookup                `option:"mandatory" validate:"required"`
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
		return Response{}, fmt.Errorf("validate request: %w", err)
	}

	log := u.logger.WithAttrs(
		slog.String("subject_id", req.SubjectID.String()),
		slog.String("code_type", req.CodeType.ToString()),
	)

	profile, err := u.profiles.GetBySubjectID(ctx, req.SubjectID)
	if err != nil {
		log.ErrorContext(ctx, "failed to get profile", logger3.Error(err))
		return Response{}, fmt.Errorf("failed to get profile: %w", err)
	}

	var targetConfirm string
	switch req.CodeType {
	case shared2.ConfirmationTypeEmail:
		if profile.Email == "" {
			return Response{}, confirmationcodeservice.ErrInvalidEmail
		}
		targetConfirm = profile.Email
	case shared2.ConfirmationTypeTgBot:
		if !profile.TelegramChatID.Valid || profile.TelegramChatID.Int64 == 0 {
			return Response{}, confirmationcodeservice.ErrTelegramNotLinked
		}
		targetConfirm = strconv.FormatInt(profile.TelegramChatID.Int64, 10)
	case shared2.ConfirmationTypePhone:
		if profile.Phone == nil || *profile.Phone <= 0 {
			return Response{}, confirmationcodeservice.ErrInvalidPhone
		}

		targetConfirm = strconv.FormatInt(*profile.Phone, 10)
	default:
		return Response{}, errors.New("unsupported confirmation type")
	}

	err = u.trx.RunInTx(ctx, func(ctx context.Context) error {
		return u.confirmationService.GenerateAndSaveCode(
			ctx, req.SubjectID, req.CodeType, shared2.ConfirmationPurposeConfirmation, targetConfirm,
		)
	})
	if err != nil {
		log.ErrorContext(ctx, "failed to send confirmation code", logger3.Error(err))
		return Response{}, fmt.Errorf("failed to send confirmation code: %w", err)
	}

	return Response{
		Success: true,
		Message: "Код успешно отправлен.",
	}, nil
}
