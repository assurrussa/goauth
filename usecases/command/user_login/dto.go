package userlogin

import (
	sharedtypes "github.com/assurrussa/goshared/pkg/sharedtypes"
	"github.com/assurrussa/goshared/pkg/validator"

	authcore "github.com/assurrussa/goauth/core"
)

type Request struct {
	ID       sharedtypes.RequestID `validate:"required"`
	Email    string                `validate:"required|email"`
	Password string                `validate:"required"` //nolint:gosec // expected struct field
}

func (r Request) Validate() error {
	return validator.Validator.Struct(r)
}

type Response struct {
	SubjectID        authcore.SubjectID
	Domain           string
	AccessToken      string //nolint:gosec // expected struct field
	RefreshToken     string //nolint:gosec // expected struct field
	ExpiresIn        int64
	ExpiresRefreshIn int64
}
