package usertokenlist

import (
	"time"

	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
)

// Request parameters for the user tokens list use case.
type Request struct {
	ID           sharedtypes.RequestID `validate:"required"`
	SubjectID    authcore.SubjectID    `validate:"required"`
	CurrentToken string                `validate:"required"`
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

// Response from the user tokens list use case.
type Response struct {
	Tokens []TokenInfo `json:"tokens"`
}

// TokenInfo represents information about a refresh token.
type TokenInfo struct {
	ID             int64     `json:"id"`
	Token          string    `json:"token"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedAt      time.Time `json:"createdAt"`
	IsCurrentToken bool      `json:"isCurrentToken"`
}
