// Package nethttp adapts goauth to standard-library JSON HTTP handlers.
package nethttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/assurrussa/goauth"
)

const (
	authContextLocalKey = "goauth.v2.auth_context"
	acceptedResponseKey = "accepted"
)

type Runtime interface {
	Logout(ctx context.Context, subjectID goauth.SubjectID, sessionID string) error
	LogoutAll(ctx context.Context, subjectID goauth.SubjectID) (int64, error)
	ChangePassword(ctx context.Context, request goauth.ChangePasswordRequest) (goauth.Account, error)
	RequestEmailChange(ctx context.Context, subjectID goauth.SubjectID, email string) error
	ConfirmEmailChange(ctx context.Context, subjectID goauth.SubjectID, code string) (goauth.Account, error)
	Register(ctx context.Context, request goauth.RegisterRequest) (goauth.RegisterResult, error)
	Login(ctx context.Context, request goauth.LoginRequest) (goauth.LoginResult, error)
	Refresh(ctx context.Context, refreshToken string) (goauth.TokenPair, error)
	AuthenticateSession(ctx context.Context, accessToken string) (goauth.AuthContext, error)
	VerifyJWT(ctx context.Context, accessToken string) (goauth.AuthContext, error)
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

func (a *Adapter) Register(w http.ResponseWriter, r *http.Request) {
	var request registerRequest
	if err := decode(w, r, &request); err != nil {
		WriteError(w, goauth.ErrInvalidIdentifier)
		return
	}
	result, err := a.runtime.Register(r.Context(), goauth.RegisterRequest{
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
		WriteError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, registerResponse{
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

func (a *Adapter) Login(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	if err := decode(w, r, &request); err != nil {
		WriteError(w, goauth.ErrInvalidCredentials)
		return
	}
	result, err := a.runtime.Login(r.Context(), goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: request.Scheme, Value: request.Identifier},
			Password:   request.Password,
		},
		Realm: request.Realm,
	})
	if err != nil {
		WriteError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		Account: accountResponseFrom(result.Account),
		Tokens:  tokenResponseFrom(result.Tokens),
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func (a *Adapter) Refresh(w http.ResponseWriter, r *http.Request) {
	var request refreshRequest
	if err := decode(w, r, &request); err != nil {
		WriteError(w, goauth.ErrInvalidToken)
		return
	}
	pair, err := a.runtime.Refresh(r.Context(), request.RefreshToken)
	if err != nil {
		WriteError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, tokenResponseFrom(pair))
}

type requestPasswordResetRequest struct {
	Email string `json:"email"`
}

func (a *Adapter) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var request requestPasswordResetRequest
	if err := decode(w, r, &request); err != nil {
		writeJSON(w, http.StatusAccepted, map[string]bool{acceptedResponseKey: true})
		return
	}
	if err := a.runtime.RequestPasswordReset(r.Context(), request.Email); err != nil {
		WriteError(w, err)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]bool{acceptedResponseKey: true})
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

func (a *Adapter) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var request resetPasswordRequest
	if err := decode(w, r, &request); err != nil {
		WriteError(w, goauth.ErrInvalidToken)
		return
	}
	if err := a.runtime.ResetPassword(r.Context(), request.Token, request.NewPassword); err != nil {
		WriteError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *Adapter) SendEmailChallenge(w http.ResponseWriter, r *http.Request) {
	auth, ok := AuthContext(r.Context())
	if !ok {
		WriteError(w, goauth.ErrInvalidToken)
		return
	}
	if err := a.runtime.SendEmailChallenge(
		r.Context(),
		auth.SubjectID,
		goauth.EmailChallengePurposeVerification,
	); err != nil {
		WriteError(w, err)
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]bool{acceptedResponseKey: true})
}

type verifyEmailChallengeRequest struct {
	Code string `json:"code"`
}

func (a *Adapter) VerifyEmailChallenge(w http.ResponseWriter, r *http.Request) {
	auth, ok := AuthContext(r.Context())
	if !ok {
		WriteError(w, goauth.ErrInvalidToken)
		return
	}
	var request verifyEmailChallengeRequest
	if err := decode(w, r, &request); err != nil {
		WriteError(w, goauth.ErrInvalidConfirmationCode)
		return
	}
	account, err := a.runtime.VerifyEmailChallenge(
		r.Context(),
		auth.SubjectID,
		goauth.EmailChallengePurposeVerification,
		request.Code,
	)
	if err != nil {
		WriteError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, accountResponseFrom(account))
}

// RealmMiddlewareOptions controls session verification. The zero value checks
// persisted session and subject state on every request.
type RealmMiddlewareOptions struct {
	// OfflineJWT skips revocation checks; use only where up to five minutes of
	// stale authorization is explicitly acceptable.
	OfflineJWT        bool
	AllowConfirmation bool
}

func (a *Adapter) RequireRealm(realm goauth.Realm, options RealmMiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.Header.Values("Authorization")) != 1 {
				WriteError(w, goauth.ErrInvalidToken)
				return
			}
			token, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				WriteError(w, goauth.ErrInvalidToken)
				return
			}
			var auth goauth.AuthContext
			var err error
			if options.OfflineJWT {
				auth, err = a.runtime.VerifyJWT(r.Context(), token)
			} else {
				auth, err = a.runtime.AuthenticateSession(r.Context(), token)
			}
			if err != nil {
				WriteError(w, err)
				return
			}
			if auth.Realm != realm {
				WriteError(w, goauth.ErrMembershipDenied)
				return
			}
			if auth.Scope == goauth.SessionScopeConfirmation && !options.AllowConfirmation {
				WriteError(w, goauth.ErrEmailVerificationRequired)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, auth)))
		})
	}
}

type authContextKey struct{}

func AuthContext(ctx context.Context) (goauth.AuthContext, bool) {
	auth, ok := ctx.Value(authContextKey{}).(goauth.AuthContext)
	return auth, ok && !auth.SubjectID.IsZero() && auth.SessionID != ""
}

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func WriteError(w http.ResponseWriter, err error) {
	status, code, message := mapError(err)
	if retryAfter, ok := retryAfterSeconds(err); ok {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	writeJSON(w, status, ErrorResponse{Error: ErrorBody{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func decode(w http.ResponseWriter, r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("expected one JSON object")
	}
	return nil
}

func mapError(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, goauth.ErrPasswordHashOverloaded):
		return http.StatusServiceUnavailable, "password_hash_overloaded", "authentication temporarily unavailable"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusServiceUnavailable, "authentication_unavailable", "authentication temporarily unavailable"
	case errors.Is(err, goauth.ErrOperationOutcomeUnknown):
		return http.StatusServiceUnavailable, "operation_outcome_unknown", "operation outcome unknown"
	case errors.Is(err, goauth.ErrAuthenticationRateLimited):
		return http.StatusTooManyRequests, "authentication_rate_limited", "too many authentication attempts"
	case errors.Is(err, goauth.ErrInvalidCredentials):
		return http.StatusUnauthorized, "invalid_credentials", "invalid credentials"
	case errors.Is(err, goauth.ErrInvalidToken), errors.Is(err, goauth.ErrExpiredToken),
		errors.Is(err, goauth.ErrSessionRevoked), errors.Is(err, goauth.ErrSecurityVersionMismatch):
		return http.StatusUnauthorized, "invalid_token", "invalid or expired token"
	case errors.Is(err, goauth.ErrMembershipDenied):
		return http.StatusForbidden, "membership_denied", "realm membership denied"
	case errors.Is(err, goauth.ErrEmailVerificationRequired):
		return http.StatusForbidden, "email_verification_required", "verified email required"
	case errors.Is(err, goauth.ErrAccountUnavailable):
		return http.StatusForbidden, "account_unavailable", "account unavailable"
	case errors.Is(err, goauth.ErrIdentifierAlreadyExists):
		return http.StatusConflict, "identifier_exists", "identifier already exists"
	case errors.Is(err, goauth.ErrInvalidIdentifier), errors.Is(err, goauth.ErrInvalidPassword),
		errors.Is(err, goauth.ErrCommonPassword), errors.Is(err, goauth.ErrInvalidConfirmationCode):
		return http.StatusUnprocessableEntity, "validation_failed", "request validation failed"
	case errors.Is(err, goauth.ErrConfirmationAttempts):
		return http.StatusTooManyRequests, "confirmation_attempts_exhausted", "confirmation attempts exhausted"
	case errors.Is(err, goauth.ErrConfirmationRateLimited):
		return http.StatusTooManyRequests, "confirmation_rate_limited", "confirmation rate limited"
	case errors.Is(err, goauth.ErrConfirmationResendDelay):
		return http.StatusTooManyRequests, "confirmation_resend_delay", "wait before resending confirmation"
	case errors.Is(err, goauth.ErrConfirmationExpired), errors.Is(err, goauth.ErrResetAlreadyUsed):
		return http.StatusBadRequest, "one_time_secret_invalid", "one-time secret is invalid or expired"
	case errors.Is(err, goauth.ErrRefreshReplay):
		return http.StatusUnauthorized, "refresh_replay", "refresh token replay detected"
	default:
		return http.StatusInternalServerError, "internal_error", "internal server error"
	}
}

func retryAfterSeconds(err error) (int, bool) {
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
