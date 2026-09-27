package localjwt

import (
	cleanerconfirmationcode "github.com/assurrussa/goauth/internal/legacy/usecases/command/cleaner_confirmation_code"
	cleanerpasswordresettokens "github.com/assurrussa/goauth/internal/legacy/usecases/command/cleaner_password_reset_tokens"
	cleanertokens "github.com/assurrussa/goauth/internal/legacy/usecases/command/cleaner_tokens"
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
	getconfirmationinformation "github.com/assurrussa/goauth/internal/legacy/usecases/query/get_confirmation_information"
	userauthme "github.com/assurrussa/goauth/internal/legacy/usecases/query/user_auth_me"
	usertokenlist "github.com/assurrussa/goauth/internal/legacy/usecases/query/user_token_list"
)

type (
	UserAuthMeUseCase  = userauthme.UseCase
	UserAuthMeRequest  = userauthme.Request
	UserAuthMeResponse = userauthme.Response
)

type (
	UserLoginUseCase  = userlogin.UseCase
	UserLoginRequest  = userlogin.Request
	UserLoginResponse = userlogin.Response
)

type (
	UserLogoutUseCase  = userlogout.UseCase
	UserLogoutRequest  = userlogout.Request
	UserLogoutResponse = userlogout.Response
)

type (
	UserLogoutAllUseCase  = userlogoutall.UseCase
	UserLogoutAllRequest  = userlogoutall.Request
	UserLogoutAllResponse = userlogoutall.Response
)

type (
	UserRegisterUseCase  = userregister.UseCase
	UserRegisterRequest  = userregister.Request
	UserRegisterResponse = userregister.Response
)

type (
	UserTokenBanUseCase  = usertokenban.UseCase
	UserTokenBanRequest  = usertokenban.Request
	UserTokenBanResponse = usertokenban.Response
)

type (
	UserTokenRevokeUseCase  = usertokenrevoke.UseCase
	UserTokenRevokeRequest  = usertokenrevoke.Request
	UserTokenRevokeResponse = usertokenrevoke.Response
)

type (
	UserTokenListUseCase  = usertokenlist.UseCase
	UserTokenListRequest  = usertokenlist.Request
	UserTokenListItem     = usertokenlist.TokenInfo
	UserTokenListResponse = usertokenlist.Response
)

type (
	UserTokenRefreshUseCase  = usertokenrefresh.UseCase
	UserTokenRefreshRequest  = usertokenrefresh.Request
	UserTokenRefreshResponse = usertokenrefresh.Response
)

type (
	SendConfirmationCodeUseCase  = sendconfirmationcode.UseCase
	SendConfirmationCodeRequest  = sendconfirmationcode.Request
	SendConfirmationCodeResponse = sendconfirmationcode.Response
)

type (
	VerifyConfirmationCodeUseCase  = verifyconfirmationcode.UseCase
	VerifyConfirmationCodeRequest  = verifyconfirmationcode.Request
	VerifyConfirmationCodeResponse = verifyconfirmationcode.Response
)

type (
	GetConfirmationInformationUseCase = getconfirmationinformation.UseCase
	GetConfirmationInformationQuery   = getconfirmationinformation.Query
	GetConfirmationInformationResult  = getconfirmationinformation.Result
)

type (
	RequestPasswordResetUseCase  = requestpasswordreset.UseCase
	RequestPasswordResetRequest  = requestpasswordreset.Request
	RequestPasswordResetResponse = requestpasswordreset.Response
)

type (
	PerformPasswordResetUseCase  = performpasswordreset.UseCase
	PerformPasswordResetRequest  = performpasswordreset.Request
	PerformPasswordResetResponse = performpasswordreset.Response
)

type (
	CleanerTokensUseCase  = cleanertokens.UseCase
	CleanerTokensRequest  = cleanertokens.Request
	CleanerTokensResponse = cleanertokens.Response
)

type (
	CleanerPasswordResetsUseCase  = cleanerpasswordresettokens.UseCase
	CleanerPasswordResetsRequest  = cleanerpasswordresettokens.Request
	CleanerPasswordResetsResponse = cleanerpasswordresettokens.Response
)

type (
	CleanerConfirmationCodesUseCase  = cleanerconfirmationcode.UseCase
	CleanerConfirmationCodesRequest  = cleanerconfirmationcode.Request
	CleanerConfirmationCodesResponse = cleanerconfirmationcode.Response
)

var (
	ErrInvalidPasswordVersion      = userauthme.ErrInvalidPasswordVersion
	ErrInvalidLoginRequest         = userlogin.ErrInvalidRequest
	ErrInvalidLogoutRequest        = userlogout.ErrInvalidRequest
	ErrInvalidLogoutAllRequest     = userlogoutall.ErrInvalidRequest
	ErrInvalidRegisterRequest      = userregister.ErrInvalidRequest
	ErrInvalidTokenRefreshRequest  = usertokenrefresh.ErrInvalidRequest
	ErrInvalidConfirmationRequest  = verifyconfirmationcode.ErrInvalidRequest
	ErrInvalidPasswordResetRequest = performpasswordreset.ErrInvalidRequest
	ErrInvalidPasswordResetToken   = performpasswordreset.ErrInvalidToken
	ErrInvalidPasswordResetConfirm = performpasswordreset.ErrInvalidPasswordConfirm
)
