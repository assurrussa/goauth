package localjwt

import (
	"context"

	logger "github.com/assurrussa/gologger"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	outbox "github.com/assurrussa/goauth/internal/legacy/infrastructure/outbox"
	"github.com/assurrussa/goauth/internal/legacy/local/passwordreset"
	"github.com/assurrussa/goauth/internal/legacy/service/authjwtservice"
	"github.com/assurrussa/goauth/internal/legacy/service/confirmationcodeservice"
	performpasswordreset "github.com/assurrussa/goauth/internal/legacy/usecases/command/perform_password_reset"
	requestpasswordreset "github.com/assurrussa/goauth/internal/legacy/usecases/command/request_password_reset"
	sendconfirmationcode "github.com/assurrussa/goauth/internal/legacy/usecases/command/send_confirmation_code"
	userlogin "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_login"
	userlogout "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_logout"
	userlogoutall "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_logout_all"
	userregister "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_register"
	usertokenban "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_token_ban"
	usertokenrefresh "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_token_refresh"
	usertokenrevoke "github.com/assurrussa/goauth/internal/legacy/usecases/command/user_token_revoke"
	verifyconfirmationcode "github.com/assurrussa/goauth/internal/legacy/usecases/command/verify_confirmation_code"
	userauthme "github.com/assurrussa/goauth/internal/legacy/usecases/query/user_auth_me"
	usertokenlist "github.com/assurrussa/goauth/internal/legacy/usecases/query/user_token_list"
)

type TokenDeleteStore interface {
	Delete(ctx context.Context, subjectID authcore.SubjectID, token string) (bool, error)
}

func NewUserAuthMeUseCase(
	logger logger.Logger,
	subjects authcore.SubjectLookup,
	profiles authcore.ProfileLookup,
	tokens TokenDeleteStore,
) (*UserAuthMeUseCase, error) {
	return userauthme.New(userauthme.NewOptions(logger, subjects, profiles, tokens))
}

func NewUserLoginUseCase(logger logger.Logger, authService *authjwtservice.Service) (*UserLoginUseCase, error) {
	return userlogin.New(userlogin.NewOptions(logger, authService))
}

func NewUserLogoutUseCase(logger logger.Logger, authService *authjwtservice.Service) (*UserLogoutUseCase, error) {
	return userlogout.New(userlogout.NewOptions(logger, authService))
}

func NewUserLogoutAllUseCase(logger logger.Logger, authService *authjwtservice.Service) (*UserLogoutAllUseCase, error) {
	return userlogoutall.New(userlogoutall.NewOptions(logger, authService))
}

func NewUserRegisterUseCase(logger logger.Logger, authService *authjwtservice.Service) (*UserRegisterUseCase, error) {
	return userregister.New(userregister.NewOptions(logger, authService))
}

func NewUserTokenBanUseCase(logger logger.Logger, authService *authjwtservice.Service) (*UserTokenBanUseCase, error) {
	return usertokenban.New(usertokenban.NewOptions(logger, authService))
}

func NewUserTokenRevokeUseCase(logger logger.Logger, authService *authjwtservice.Service) (*UserTokenRevokeUseCase, error) {
	return usertokenrevoke.New(usertokenrevoke.NewOptions(logger, authService))
}

func NewUserTokenListUseCase(logger logger.Logger, authService *authjwtservice.Service) (*UserTokenListUseCase, error) {
	return usertokenlist.New(usertokenlist.NewOptions(logger, authService))
}

func NewUserTokenRefreshUseCase(logger logger.Logger, authService *authjwtservice.Service) (*UserTokenRefreshUseCase, error) {
	return usertokenrefresh.New(usertokenrefresh.NewOptions(logger, authService))
}

func NewSendConfirmationCodeUseCase(
	logger logger.Logger,
	confirmation *confirmationcodeservice.Service,
	profiles authcore.ProfileLookup,
	tx outbox.StoragePgsqlTxManager,
) (*SendConfirmationCodeUseCase, error) {
	return sendconfirmationcode.New(sendconfirmationcode.NewOptions(logger, confirmation, profiles, tx))
}

func NewVerifyConfirmationCodeUseCase(
	logger logger.Logger,
	confirmation *confirmationcodeservice.Service,
	tx outbox.StoragePgsqlTxManager,
) (*VerifyConfirmationCodeUseCase, error) {
	return verifyconfirmationcode.New(verifyconfirmationcode.NewOptions(logger, confirmation, tx))
}

func NewRequestPasswordResetUseCase(
	logger logger.Logger,
	service *passwordreset.Service,
) (*RequestPasswordResetUseCase, error) {
	return requestpasswordreset.New(requestpasswordreset.NewOptions(logger, service))
}

func NewPerformPasswordResetUseCase(
	logger logger.Logger,
	service *passwordreset.Service,
) (*PerformPasswordResetUseCase, error) {
	return performpasswordreset.New(performpasswordreset.NewOptions(logger, service))
}
