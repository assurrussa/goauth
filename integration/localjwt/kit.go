package localjwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/jackc/pgx/v5"

	authcore "github.com/assurrussa/goauth/core"
	"github.com/assurrussa/goauth/infrastructure/notify"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	"github.com/assurrussa/goauth/local/confirmation"
	"github.com/assurrussa/goauth/local/passwordreset"
	"github.com/assurrussa/goauth/service/authinvalidator"
	"github.com/assurrussa/goauth/service/authjwtservice"
	"github.com/assurrussa/goauth/service/confirmationcodeservice"
	"github.com/assurrussa/goauth/service/userconfirmationservice"
	cleanerconfirmationcode "github.com/assurrussa/goauth/usecases/command/cleaner_confirmation_code"
	cleanerpasswordresettokens "github.com/assurrussa/goauth/usecases/command/cleaner_password_reset_tokens"
	cleanertokens "github.com/assurrussa/goauth/usecases/command/cleaner_tokens"
	performpasswordreset "github.com/assurrussa/goauth/usecases/command/perform_password_reset"
	requestpasswordreset "github.com/assurrussa/goauth/usecases/command/request_password_reset"
	sendconfirmationcode "github.com/assurrussa/goauth/usecases/command/send_confirmation_code"
	userlogin "github.com/assurrussa/goauth/usecases/command/user_login"
	userlogout "github.com/assurrussa/goauth/usecases/command/user_logout"
	userlogoutall "github.com/assurrussa/goauth/usecases/command/user_logout_all"
	userregister "github.com/assurrussa/goauth/usecases/command/user_register"
	usertokenban "github.com/assurrussa/goauth/usecases/command/user_token_ban"
	usertokenrefresh "github.com/assurrussa/goauth/usecases/command/user_token_refresh"
	usertokenrevoke "github.com/assurrussa/goauth/usecases/command/user_token_revoke"
	verifyconfirmationcode "github.com/assurrussa/goauth/usecases/command/verify_confirmation_code"
	getconfirmationinformation "github.com/assurrussa/goauth/usecases/query/get_confirmation_information"
	userauthme "github.com/assurrussa/goauth/usecases/query/user_auth_me"
	usertokenlist "github.com/assurrussa/goauth/usecases/query/user_token_list"
)

type NotificationService interface {
	SendToChannel(
		ctx context.Context,
		channel notify.NotificationChannel,
		notification *notify.Notification,
		recipients ...*notify.Recipient,
	) ([]*notify.NotificationResult, error)
}

type OutboxPutter interface {
	Put(ctx context.Context, name, payload string, availableAt time.Time) (outbox.JobID, error)
}

type Options struct {
	Logger                      logger.Logger
	Reader                      authcore.SubjectReader
	Lookup                      authcore.SubjectLookup
	Writer                      authcore.SubjectWriter
	Tokens                      authcore.RefreshTokenStore
	Issuer                      authcore.TokenIssuer
	PasswordResets              authcore.PasswordResetStore
	Hasher                      authcore.PasswordHasher
	Tx                          authcore.TxManager
	Profiles                    authcore.ProfileLookup
	ProfileProvisioner          authcore.ProfileProvisioner
	Projections                 authcore.ProfileProjectionWriter
	ConfirmationSubjects        confirmationcodeservice.SubjectConfirmationStore
	ConfirmationCodes           confirmation.CodeRepository
	Confirmations               confirmation.RecordRepository
	Notification                NotificationService
	Outbox                      OutboxPutter
	BaseURL                     string
	ResetTTLMinutes             int
	ConfirmationCodeExpiration  time.Duration
	ConfirmationMinResendDelay  time.Duration
	ConfirmationPerHourLimit    int
	ConfirmationPerDayLimit     int
	CleanupBatchSize            int
	CleanupPasswordResetMinutes int
	CleanupConfirmationMinutes  int
	CleanupTokenMinutes         int
}

type Services struct {
	Auth              *authjwtservice.Service
	PasswordReset     *passwordreset.Service
	ConfirmationCodes *confirmationcodeservice.Service
	UserConfirmations *userconfirmationservice.Service
}

type UseCases struct {
	UserAuthMe                 *userauthme.UseCase
	UserLogin                  *userlogin.UseCase
	UserLogout                 *userlogout.UseCase
	UserLogoutAll              *userlogoutall.UseCase
	UserRegister               *userregister.UseCase
	UserTokenBan               *usertokenban.UseCase
	UserTokenRevoke            *usertokenrevoke.UseCase
	UserTokenList              *usertokenlist.UseCase
	UserTokenRefresh           *usertokenrefresh.UseCase
	SendConfirmationCode       *sendconfirmationcode.UseCase
	VerifyConfirmationCode     *verifyconfirmationcode.UseCase
	GetConfirmationInformation *getconfirmationinformation.UseCase
	RequestPasswordReset       *requestpasswordreset.UseCase
	PerformPasswordReset       *performpasswordreset.UseCase
	CleanerTokens              *cleanertokens.UseCase
	CleanerPasswordResets      *cleanerpasswordresettokens.UseCase
	CleanerConfirmationCodes   *cleanerconfirmationcode.UseCase
}

type Kit struct {
	Services Services
	UseCases UseCases
}

//nolint:gocognit // this function sets up many dependencies
func New(opts Options) (*Kit, error) { //nolint:gocyclo // autofix
	switch {
	case opts.Reader == nil:
		return nil, errors.New("localjwt: reader is required")
	case opts.Lookup == nil:
		return nil, errors.New("localjwt: lookup is required")
	case opts.Writer == nil:
		return nil, errors.New("localjwt: writer is required")
	case opts.Tokens == nil:
		return nil, errors.New("localjwt: refresh token store is required")
	case opts.Issuer == nil:
		return nil, errors.New("localjwt: token issuer is required")
	case opts.PasswordResets == nil:
		return nil, errors.New("localjwt: password reset store is required")
	case opts.Hasher == nil:
		return nil, errors.New("localjwt: hasher is required")
	case opts.Tx == nil:
		return nil, errors.New("localjwt: tx manager is required")
	case opts.Profiles == nil:
		return nil, errors.New("localjwt: profile lookup is required")
	case opts.Projections == nil:
		return nil, errors.New("localjwt: profile projection writer is required")
	case opts.ConfirmationSubjects == nil:
		return nil, errors.New("localjwt: confirmation subjects is required")
	case opts.ConfirmationCodes == nil:
		return nil, errors.New("localjwt: confirmation code repo is required")
	case opts.Confirmations == nil:
		return nil, errors.New("localjwt: confirmation repo is required")
	case opts.Outbox == nil:
		return nil, errors.New("localjwt: outbox is required")
	}

	if opts.Logger == nil {
		opts.Logger = logger.Discard()
	}
	if opts.Notification == nil {
		opts.Notification = noopNotificationService{}
	}
	if opts.ResetTTLMinutes <= 0 {
		opts.ResetTTLMinutes = 60
	}
	if opts.CleanupBatchSize <= 0 {
		opts.CleanupBatchSize = 100
	}
	if opts.CleanupPasswordResetMinutes <= 0 {
		opts.CleanupPasswordResetMinutes = 60
	}
	if opts.CleanupConfirmationMinutes <= 0 {
		opts.CleanupConfirmationMinutes = 60
	}
	if opts.CleanupTokenMinutes <= 0 {
		opts.CleanupTokenMinutes = 60
	}

	tx := asPGSQLTxManager(opts.Tx)
	profileProvisioner := opts.ProfileProvisioner
	if profileProvisioner == nil {
		if provisioner, ok := opts.Profiles.(authcore.ProfileProvisioner); ok {
			profileProvisioner = provisioner
		}
	}

	authService, err := authjwtservice.New(authjwtservice.NewOptions(
		opts.Reader,
		opts.Lookup,
		opts.Writer,
		opts.Tokens,
		opts.Issuer,
		opts.Hasher,
		opts.Tx,
		authjwtservice.WithProfileProvisioner(profileProvisioner),
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build auth service: %w", err)
	}

	invalidator, err := authinvalidator.New(authinvalidator.Options{
		RefreshTokens: opts.Tokens,
	})
	if err != nil {
		return nil, fmt.Errorf("localjwt: build password invalidator: %w", err)
	}

	passwordResetService, err := passwordreset.New(passwordreset.Options{
		Reader:      opts.Reader,
		Writer:      opts.Writer,
		Tokens:      opts.PasswordResets,
		Hasher:      opts.Hasher,
		Tx:          opts.Tx,
		Outbox:      opts.Outbox,
		BaseURL:     opts.BaseURL,
		TTLMinutes:  opts.ResetTTLMinutes,
		Invalidator: invalidator,
	})
	if err != nil {
		return nil, fmt.Errorf("localjwt: build password reset service: %w", err)
	}

	confirmationService, err := confirmationcodeservice.New(confirmationcodeservice.NewOptions(
		opts.Notification,
		opts.ConfirmationCodes,
		opts.Profiles,
		opts.Projections,
		opts.ConfirmationSubjects,
		opts.Confirmations,
		opts.Logger,
		opts.Outbox,
		confirmationcodeservice.WithCodeExpiration(opts.ConfirmationCodeExpiration),
		confirmationcodeservice.WithMinResendInterval(opts.ConfirmationMinResendDelay),
		confirmationcodeservice.WithPerHourLimit(opts.ConfirmationPerHourLimit),
		confirmationcodeservice.WithPerDayLimit(opts.ConfirmationPerDayLimit),
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build confirmation service: %w", err)
	}

	userConfirmationService, err := userconfirmationservice.New(userconfirmationservice.NewOptions(
		opts.Logger,
		opts.Confirmations,
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user confirmation service: %w", err)
	}

	userAuthMeUseCase, err := userauthme.New(userauthme.NewOptions(
		opts.Logger,
		opts.Lookup,
		opts.Profiles,
		tokenDeleteAdapter{tokens: opts.Tokens},
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user auth me usecase: %w", err)
	}

	userLoginUseCase, err := userlogin.New(userlogin.NewOptions(opts.Logger, authService))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user login usecase: %w", err)
	}
	userLogoutUseCase, err := userlogout.New(userlogout.NewOptions(opts.Logger, authService))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user logout usecase: %w", err)
	}
	userLogoutAllUseCase, err := userlogoutall.New(userlogoutall.NewOptions(opts.Logger, authService))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user logout all usecase: %w", err)
	}
	userRegisterUseCase, err := userregister.New(userregister.NewOptions(opts.Logger, authService))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user register usecase: %w", err)
	}
	userTokenBanUseCase, err := usertokenban.New(usertokenban.NewOptions(opts.Logger, authService))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user token ban usecase: %w", err)
	}
	userTokenRevokeUseCase, err := usertokenrevoke.New(usertokenrevoke.NewOptions(opts.Logger, authService))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user token revoke usecase: %w", err)
	}
	userTokenListUseCase, err := usertokenlist.New(usertokenlist.NewOptions(opts.Logger, authService))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user token list usecase: %w", err)
	}
	userTokenRefreshUseCase, err := usertokenrefresh.New(usertokenrefresh.NewOptions(opts.Logger, authService))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build user token refresh usecase: %w", err)
	}
	sendConfirmationCodeUseCase, err := sendconfirmationcode.New(sendconfirmationcode.NewOptions(
		opts.Logger,
		confirmationService,
		opts.Profiles,
		tx,
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build send confirmation usecase: %w", err)
	}
	verifyConfirmationCodeUseCase, err := verifyconfirmationcode.New(verifyconfirmationcode.NewOptions(
		opts.Logger,
		confirmationService,
		tx,
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build verify confirmation usecase: %w", err)
	}
	getConfirmationInformationUseCase, err := getconfirmationinformation.New(getconfirmationinformation.NewOptions(
		opts.Logger,
		confirmationService,
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build get confirmation information usecase: %w", err)
	}
	requestPasswordResetUseCase, err := requestpasswordreset.New(requestpasswordreset.NewOptions(
		opts.Logger,
		passwordResetService,
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build request password reset usecase: %w", err)
	}
	performPasswordResetUseCase, err := performpasswordreset.New(performpasswordreset.NewOptions(
		opts.Logger,
		passwordResetService,
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build perform password reset usecase: %w", err)
	}
	var cleanerTokensUseCase *cleanertokens.UseCase
	if tokenCleanerStorage, ok := opts.Tokens.(interface {
		CleanupExpiredTokens(ctx context.Context, batchSize int, limit int) (int64, error)
	}); ok {
		cleanerTokensUseCase, err = cleanertokens.New(cleanertokens.NewOptions(
			opts.Logger,
			tokenCleaner{tokens: tokenCleanerStorage},
			tx,
		))
		if err != nil {
			return nil, fmt.Errorf("localjwt: build token cleaner usecase: %w", err)
		}
	}

	var cleanerPasswordResetUseCase *cleanerpasswordresettokens.UseCase
	if passwordResetCleanerStorage, ok := opts.PasswordResets.(interface {
		CleanupExpiredPasswordTokens(ctx context.Context, batchSize int, limit int) (int64, error)
	}); ok {
		cleanerPasswordResetUseCase, err = cleanerpasswordresettokens.New(cleanerpasswordresettokens.NewOptions(
			opts.Logger,
			passwordResetCleaner{tokens: passwordResetCleanerStorage},
			tx,
		))
		if err != nil {
			return nil, fmt.Errorf("localjwt: build password reset cleaner usecase: %w", err)
		}
	}
	cleanerConfirmationCodesUseCase, err := cleanerconfirmationcode.New(cleanerconfirmationcode.NewOptions(
		opts.Logger,
		opts.ConfirmationCodes,
		tx,
	))
	if err != nil {
		return nil, fmt.Errorf("localjwt: build confirmation cleaner usecase: %w", err)
	}

	return &Kit{
		Services: Services{
			Auth:              authService,
			PasswordReset:     passwordResetService,
			ConfirmationCodes: confirmationService,
			UserConfirmations: userConfirmationService,
		},
		UseCases: UseCases{
			UserAuthMe:                 userAuthMeUseCase,
			UserLogin:                  userLoginUseCase,
			UserLogout:                 userLogoutUseCase,
			UserLogoutAll:              userLogoutAllUseCase,
			UserRegister:               userRegisterUseCase,
			UserTokenBan:               userTokenBanUseCase,
			UserTokenRevoke:            userTokenRevokeUseCase,
			UserTokenList:              userTokenListUseCase,
			UserTokenRefresh:           userTokenRefreshUseCase,
			SendConfirmationCode:       sendConfirmationCodeUseCase,
			VerifyConfirmationCode:     verifyConfirmationCodeUseCase,
			GetConfirmationInformation: getConfirmationInformationUseCase,
			RequestPasswordReset:       requestPasswordResetUseCase,
			PerformPasswordReset:       performPasswordResetUseCase,
			CleanerTokens:              cleanerTokensUseCase,
			CleanerPasswordResets:      cleanerPasswordResetUseCase,
			CleanerConfirmationCodes:   cleanerConfirmationCodesUseCase,
		},
	}, nil
}

type noopNotificationService struct{}

func (noopNotificationService) SendToChannel(
	context.Context,
	notify.NotificationChannel,
	*notify.Notification,
	...*notify.Recipient,
) ([]*notify.NotificationResult, error) {
	return nil, nil
}

type tokenDeleteAdapter struct {
	tokens authcore.RefreshTokenStore
}

func (a tokenDeleteAdapter) Delete(ctx context.Context, subjectID authcore.SubjectID, token string) (bool, error) {
	return a.tokens.Delete(ctx, subjectID, token)
}

type tokenCleaner struct {
	tokens interface {
		CleanupExpiredTokens(ctx context.Context, batchSize int, limit int) (int64, error)
	}
}

func (c tokenCleaner) CleanupExpiredTokens(ctx context.Context, batchSize, minutes int) (int64, error) {
	return c.tokens.CleanupExpiredTokens(ctx, batchSize, minutes)
}

type passwordResetCleaner struct {
	tokens interface {
		CleanupExpiredPasswordTokens(ctx context.Context, batchSize int, limit int) (int64, error)
	}
}

func (c passwordResetCleaner) CleanupExpiredPasswordTokens(ctx context.Context, batchSize, minutes int) (int64, error) {
	return c.tokens.CleanupExpiredPasswordTokens(ctx, batchSize, minutes)
}

func asPGSQLTxManager(tx authcore.TxManager) outbox.StoragePgsqlTxManager {
	if current, ok := tx.(outbox.StoragePgsqlTxManager); ok {
		return current
	}

	return pgsqlTxAdapter{tx: tx}
}

type pgsqlTxAdapter struct {
	tx authcore.TxManager
}

func (a pgsqlTxAdapter) RunInTx(ctx context.Context, fn func(context.Context) error) error {
	return a.tx.RunInTx(ctx, fn)
}

func (a pgsqlTxAdapter) ReadCommitted(context.Context, pgx.TxAccessMode, outbox.StoragePgsqlFnCallback) error {
	return errors.New("localjwt: ReadCommitted is not supported by core tx adapter")
}

func (a pgsqlTxAdapter) RepeatableRead(context.Context, pgx.TxAccessMode, outbox.StoragePgsqlFnCallback) error {
	return errors.New("localjwt: RepeatableRead is not supported by core tx adapter")
}

func (a pgsqlTxAdapter) Serializable(context.Context, pgx.TxAccessMode, outbox.StoragePgsqlFnCallback) error {
	return errors.New("localjwt: Serializable is not supported by core tx adapter")
}
