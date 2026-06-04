package usertokenlist

import (
	"context"
	"fmt"

	"github.com/assurrussa/goshared/pkg/logger"

	authcore "github.com/assurrussa/goauth/core"
	"github.com/assurrussa/goauth/service/authjwtservice"
)

//go:generate toolsmocks

//go:generate options-gen -out-filename=usecase_options.gen.go -from-struct=Options
type Options struct {
	logger      logger.Logger `option:"mandatory" validate:"required"`
	authService authService   `option:"mandatory" validate:"required"`
}

// UseCase represents the user tokens list use case.
type UseCase struct {
	Options
}

// authService defines the interface for the authentication service.
type authService interface {
	GetUserTokens(ctx context.Context, subjectID authcore.SubjectID, currentToken string) ([]authjwtservice.TokenInfo, error)
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

// Handle runs the use case with the given input.
func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, fmt.Errorf("validate request: %w", err)
	}

	tokens, err := u.authService.GetUserTokens(ctx, req.SubjectID, req.CurrentToken)
	if err != nil {
		return Response{}, fmt.Errorf("get user tokens: %w", err)
	}

	tokenInfos := make([]TokenInfo, 0, len(tokens))
	for _, token := range tokens {
		tokenInfos = append(tokenInfos, TokenInfo{
			ID:             token.ID,
			Token:          token.Token,
			ExpiresAt:      token.ExpiresAt,
			CreatedAt:      token.CreatedAt,
			IsCurrentToken: token.IsCurrentToken,
		})
	}

	return Response{
		Tokens: tokenInfos,
	}, nil
}
