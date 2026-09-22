package getconfirmationinformation

import (
	"context"
	"fmt"
	"strconv"

	logger "github.com/assurrussa/gologger"
	"github.com/assurrussa/goshared/pkg/pointer"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

//go:generate toolsmocks

type confirmationCodeService interface {
	GetConfirmationInfo(
		ctx context.Context,
		subjectID authcore.SubjectID,
	) (authcore.ConfirmationInfo, error)
}

//go:generate options-gen -out-filename=usecase_options.gen.go -from-struct=Options
type Options struct {
	logger                  logger.Logger           `option:"mandatory" validate:"required"`
	confirmationCodeService confirmationCodeService `option:"mandatory" validate:"required"`
}

type UseCase struct {
	Options
}

func Must(opts Options) *UseCase {
	useCase, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("fatal pgsqlinit usecase: %w", err))
	}

	return useCase
}

func New(opts Options) (*UseCase, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("error create new usercase: %w", err)
	}

	return &UseCase{Options: opts}, nil
}

func (u *UseCase) Handle(ctx context.Context, query Query) (Result, error) {
	info, err := u.confirmationCodeService.GetConfirmationInfo(ctx, query.SubjectID)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Email:            info.Profile.Email,
		Phone:            strconv.FormatInt(pointer.Indirect(info.Profile.Phone), 10),
		IsEmailConfirmed: info.Status.EmailConfirmed,
		IsPhoneConfirmed: info.Status.PhoneConfirmed,
	}, nil
}
