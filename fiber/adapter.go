package fiber

import (
	"context"
	"errors"
	"strconv"
	"strings"

	gofiber "github.com/gofiber/fiber/v3"

	"github.com/assurrussa/goauth"
)

const (
	authContextLocalKey = "goauth.v2.auth_context"
	acceptedResponseKey = "accepted"
)

type Runtime interface {
	Register(ctx context.Context, request goauth.RegisterRequest) (goauth.RegisterResult, error)
	Login(ctx context.Context, request goauth.LoginRequest) (goauth.LoginResult, error)
	Refresh(ctx context.Context, refreshToken string) (goauth.TokenPair, error)
	VerifyAccessToken(ctx context.Context, accessToken string, introspect bool) (goauth.AuthContext, error)
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	SendEmailChallenge(ctx context.Context, subjectID goauth.SubjectID, purpose goauth.EmailChallengePurpose) error
	VerifyEmailChallenge(
		ctx context.Context,
		subjectID goauth.SubjectID,
		purpose goauth.EmailChallengePurpose,
		code string,
	) (goauth.Account, error)
}

type Adapter struct {
	runtime Runtime
}

func New(runtime Runtime) (*Adapter, error) {
	if runtime == nil {
		return nil, errors.New("goauth Runtime is required")
	}

	return &Adapter{runtime: runtime}, nil
}

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	GivenName   string `json:"givenName"`
	FamilyName  string `json:"familyName"`
}

func (a *Adapter) Register(c gofiber.Ctx) error {
	var request registerRequest
	if err := c.Bind().Body(&request); err != nil {
		return WriteError(c, goauth.ErrInvalidIdentifier)
	}
	result, err := a.runtime.Register(c.Context(), goauth.RegisterRequest{
		Email:    request.Email,
		Password: request.Password,
		Profile: goauth.BasicProfile{
			Username:    request.Username,
			DisplayName: request.DisplayName,
			GivenName:   request.GivenName,
			FamilyName:  request.FamilyName,
		},
	})
	if err != nil {
		return WriteError(c, err)
	}

	return c.Status(gofiber.StatusCreated).JSON(registerResponse{
		Account: accountResponseFrom(result.Account),
		Tokens:  tokenResponseFrom(result.Tokens),
	})
}

type loginRequest struct {
	Scheme     goauth.IdentifierScheme `json:"scheme"`
	Identifier string                  `json:"identifier"`
	Password   string                  `json:"password"`
	Realm      goauth.Realm            `json:"realm"`
}

func (a *Adapter) Login(c gofiber.Ctx) error {
	var request loginRequest
	if err := c.Bind().Body(&request); err != nil {
		return WriteError(c, goauth.ErrInvalidCredentials)
	}
	result, err := a.runtime.Login(c.Context(), goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: request.Scheme, Value: request.Identifier},
			Password:   request.Password,
		},
		Realm: request.Realm,
	})
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(loginResponse{
		Account: accountResponseFrom(result.Account),
		Tokens:  tokenResponseFrom(result.Tokens),
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (a *Adapter) Refresh(c gofiber.Ctx) error {
	var request refreshRequest
	if err := c.Bind().Body(&request); err != nil {
		return WriteError(c, goauth.ErrInvalidToken)
	}
	pair, err := a.runtime.Refresh(c.Context(), request.RefreshToken)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(tokenResponseFrom(pair))
}

type requestPasswordResetRequest struct {
	Email string `json:"email"`
}

func (a *Adapter) RequestPasswordReset(c gofiber.Ctx) error {
	var request requestPasswordResetRequest
	if err := c.Bind().Body(&request); err != nil {
		return c.Status(gofiber.StatusAccepted).JSON(gofiber.Map{acceptedResponseKey: true})
	}
	if err := a.runtime.RequestPasswordReset(c.Context(), request.Email); err != nil {
		return WriteError(c, err)
	}

	return c.Status(gofiber.StatusAccepted).JSON(gofiber.Map{acceptedResponseKey: true})
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func (a *Adapter) ResetPassword(c gofiber.Ctx) error {
	var request resetPasswordRequest
	if err := c.Bind().Body(&request); err != nil {
		return WriteError(c, goauth.ErrInvalidToken)
	}
	if err := a.runtime.ResetPassword(c.Context(), request.Token, request.NewPassword); err != nil {
		return WriteError(c, err)
	}

	return c.SendStatus(gofiber.StatusNoContent)
}

func (a *Adapter) SendEmailChallenge(c gofiber.Ctx) error {
	auth, ok := AuthContext(c)
	if !ok {
		return WriteError(c, goauth.ErrInvalidToken)
	}
	if err := a.runtime.SendEmailChallenge(
		c.Context(),
		auth.SubjectID,
		goauth.EmailChallengePurposeVerification,
	); err != nil {
		return WriteError(c, err)
	}

	return c.Status(gofiber.StatusAccepted).JSON(gofiber.Map{acceptedResponseKey: true})
}

type verifyEmailChallengeRequest struct {
	Code string `json:"code"`
}

func (a *Adapter) VerifyEmailChallenge(c gofiber.Ctx) error {
	auth, ok := AuthContext(c)
	if !ok {
		return WriteError(c, goauth.ErrInvalidToken)
	}
	var request verifyEmailChallengeRequest
	if err := c.Bind().Body(&request); err != nil {
		return WriteError(c, goauth.ErrInvalidConfirmationCode)
	}
	account, err := a.runtime.VerifyEmailChallenge(
		c.Context(),
		auth.SubjectID,
		goauth.EmailChallengePurposeVerification,
		request.Code,
	)
	if err != nil {
		return WriteError(c, err)
	}

	return c.JSON(accountResponseFrom(account))
}

type RealmMiddlewareOptions struct {
	// Deprecated: session introspection is now the default.
	Introspect bool
	// OfflineJWT explicitly opts out of current session checks.
	OfflineJWT        bool
	AllowConfirmation bool
}

func (a *Adapter) RequireRealm(realm goauth.Realm, options RealmMiddlewareOptions) gofiber.Handler {
	return func(c gofiber.Ctx) error {
		if len(c.Request().Header.PeekAll(gofiber.HeaderAuthorization)) != 1 {
			return WriteError(c, goauth.ErrInvalidToken)
		}
		token, ok := bearerToken(c.Get(gofiber.HeaderAuthorization))
		if !ok {
			return WriteError(c, goauth.ErrInvalidToken)
		}
		auth, err := a.runtime.VerifyAccessToken(c.Context(), token, !options.OfflineJWT)
		if err != nil {
			return WriteError(c, err)
		}
		if auth.Realm != realm {
			return WriteError(c, goauth.ErrMembershipDenied)
		}
		if auth.Scope == goauth.SessionScopeConfirmation && !options.AllowConfirmation {
			return WriteError(c, goauth.ErrEmailVerificationRequired)
		}
		gofiber.Locals[goauth.AuthContext](c, authContextLocalKey, auth)

		return c.Next()
	}
}

func AuthContext(c gofiber.Ctx) (goauth.AuthContext, bool) {
	auth := gofiber.Locals[goauth.AuthContext](c, authContextLocalKey)
	return auth, !auth.SubjectID.IsZero() && auth.SessionID != ""
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func WriteError(c gofiber.Ctx, err error) error {
	status, code, message := mapError(err)
	if retryAfter, ok := retryAfterSeconds(err); ok {
		c.Set(gofiber.HeaderRetryAfter, strconv.Itoa(retryAfter))
	}

	return c.Status(status).JSON(ErrorResponse{Error: ErrorBody{Code: code, Message: message}})
}

func mapError(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, goauth.ErrOperationOutcomeUnknown):
		// A canceled commit may have persisted; its cause must not imply safe retry.
		return gofiber.StatusServiceUnavailable, "operation_outcome_unknown", "operation outcome is unknown; authenticate again"
	case errors.Is(err, goauth.ErrPasswordHashOverloaded):
		return gofiber.StatusServiceUnavailable, "password_hash_overloaded", "authentication temporarily unavailable"
	case errors.Is(err, goauth.ErrPasswordVerificationUnavailable),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return gofiber.StatusServiceUnavailable, "authentication_unavailable", "authentication temporarily unavailable"
	case errors.Is(err, goauth.ErrAuthenticationRateLimited):
		return gofiber.StatusTooManyRequests, "authentication_rate_limited", "too many authentication attempts"
	case errors.Is(err, goauth.ErrInvalidRealm):
		return gofiber.StatusBadRequest, "invalid_realm", "invalid realm"
	case errors.Is(err, goauth.ErrRealmNotRegistered):
		return gofiber.StatusBadRequest, "realm_not_registered", "realm is not registered"
	case errors.Is(err, goauth.ErrInvalidCredentials):
		return gofiber.StatusUnauthorized, "invalid_credentials", "invalid credentials"
	case errors.Is(err, goauth.ErrInvalidToken), errors.Is(err, goauth.ErrExpiredToken),
		errors.Is(err, goauth.ErrSessionRevoked), errors.Is(err, goauth.ErrSecurityVersionMismatch):
		return gofiber.StatusUnauthorized, "invalid_token", "invalid or expired token"
	case errors.Is(err, goauth.ErrMembershipDenied):
		return gofiber.StatusForbidden, "membership_denied", "realm membership denied"
	case errors.Is(err, goauth.ErrEmailVerificationRequired):
		return gofiber.StatusForbidden, "email_verification_required", "verified email required"
	case errors.Is(err, goauth.ErrAccountUnavailable):
		return gofiber.StatusForbidden, "account_unavailable", "account unavailable"
	case errors.Is(err, goauth.ErrIdentifierAlreadyExists):
		return gofiber.StatusConflict, "identifier_exists", "identifier already exists"
	case errors.Is(err, goauth.ErrInvalidIdentifier), errors.Is(err, goauth.ErrInvalidPassword),
		errors.Is(err, goauth.ErrCommonPassword), errors.Is(err, goauth.ErrInvalidConfirmationCode):
		return gofiber.StatusUnprocessableEntity, "validation_failed", "request validation failed"
	case errors.Is(err, goauth.ErrConfirmationAttempts):
		return gofiber.StatusTooManyRequests, "confirmation_attempts_exhausted", "confirmation attempts exhausted"
	case errors.Is(err, goauth.ErrConfirmationRateLimited):
		return gofiber.StatusTooManyRequests, "confirmation_rate_limited", "confirmation rate limited"
	case errors.Is(err, goauth.ErrConfirmationResendDelay):
		return gofiber.StatusTooManyRequests, "confirmation_resend_delay", "wait before resending confirmation"
	case errors.Is(err, goauth.ErrConfirmationExpired), errors.Is(err, goauth.ErrResetAlreadyUsed):
		return gofiber.StatusBadRequest, "one_time_secret_invalid", "one-time secret is invalid or expired"
	case errors.Is(err, goauth.ErrRefreshReplay):
		return gofiber.StatusUnauthorized, "refresh_replay", "refresh token replay detected"
	default:
		return gofiber.StatusInternalServerError, "internal_error", "internal server error"
	}
}

func retryAfterSeconds(err error) (int, bool) {
	if errors.Is(err, goauth.ErrOperationOutcomeUnknown) {
		return 0, false
	}
	if errors.Is(err, goauth.ErrPasswordHashOverloaded) {
		return 1, true
	}
	if errors.Is(err, goauth.ErrConfirmationResendDelay) {
		return 60, true
	}
	if errors.Is(err, goauth.ErrConfirmationRateLimited) {
		return 3600, true
	}
	if errors.Is(err, goauth.ErrAuthenticationRateLimited) {
		return 900, true
	}

	return 0, false
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(strings.TrimSpace(header))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}

	return parts[1], true
}
