package userauthme

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goshared/pkg/logger"

	authcore "github.com/assurrussa/goauth/core"
)

var ErrInvalidPasswordVersion = errors.New("invalid password version")

//go:generate toolsmocks

type subjectLookup interface {
	GetByID(ctx context.Context, subjectID authcore.SubjectID) (authcore.Subject, error)
}

type profileLookup interface {
	GetBySubjectID(ctx context.Context, subjectID authcore.SubjectID) (authcore.Profile, error)
}

type repoToken interface {
	Delete(ctx context.Context, subjectID authcore.SubjectID, token string) (bool, error)
}

//go:generate options-gen -out-filename=usecase_options.gen.go -from-struct=Options
type Options struct {
	logger    logger.Logger `option:"mandatory" validate:"required"`
	subjects  subjectLookup `option:"mandatory" validate:"required"`
	profiles  profileLookup `option:"mandatory" validate:"required"`
	repoToken repoToken     `option:"mandatory" validate:"required"`
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

	subject, err := u.subjects.GetByID(ctx, req.SubjectID)
	if err != nil {
		return Response{}, fmt.Errorf("get subject: %w", err)
	}

	if req.Version != subject.PasswordVersion {
		if _, err := u.repoToken.Delete(ctx, req.SubjectID, req.Token); err != nil {
			return Response{}, fmt.Errorf("delete refresh token: %w", errors.Join(err, ErrInvalidPasswordVersion))
		}

		return Response{}, ErrInvalidPasswordVersion
	}

	profile, err := u.profiles.GetBySubjectID(ctx, req.SubjectID)
	if err != nil {
		return Response{}, fmt.Errorf("get profile: %w", err)
	}

	return Response{
		Profile: profile,
	}, nil
}
