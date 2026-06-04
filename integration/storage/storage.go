package storage

import (
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
	confirmationcoderepo "github.com/assurrussa/goauth/storage/pgsql/confirmationcoderepo"
	confirmationrepo "github.com/assurrussa/goauth/storage/pgsql/confirmationrepo"
	emailchangerepo "github.com/assurrussa/goauth/storage/pgsql/emailchangerepo"
	identitylinkrepo "github.com/assurrussa/goauth/storage/pgsql/identitylinkrepo"
	oidcrefreshtokenrepo "github.com/assurrussa/goauth/storage/pgsql/oidcrefreshtokenrepo"
	passwordresettokenrepo "github.com/assurrussa/goauth/storage/pgsql/passwordresettokenrepo"
	refreshtokenrepo "github.com/assurrussa/goauth/storage/pgsql/refreshtokenrepo"
	sessionrepo "github.com/assurrussa/goauth/storage/pgsql/sessionrepo"
	subjectrepo "github.com/assurrussa/goauth/storage/pgsql/subjectrepo"
	oidcstate "github.com/assurrussa/goauth/storage/redis/oidcstate"
)

type (
	ConfirmationCodeRepo = confirmationcoderepo.Repo
	ConfirmationRepo     = confirmationrepo.Repo
	EmailChangeRepo      = emailchangerepo.Repo
	IdentityLinkRepo     = identitylinkrepo.Repo

	OIDCRefreshTokenRepo                 = oidcrefreshtokenrepo.Repo
	OIDCRefreshTokenRepoOptions          = oidcrefreshtokenrepo.Options
	OIDCRefreshTokenRepoOptOptionsSetter = oidcrefreshtokenrepo.OptOptionsSetter

	PasswordResetTokenRepo = passwordresettokenrepo.Repo
	RefreshTokenRepo       = refreshtokenrepo.Repo
	SessionRepo            = sessionrepo.Repo
	SubjectRepo            = subjectrepo.Repo

	OIDCStateRedisClient = oidcstate.RedisClient
	OIDCRequestStore     = oidcstate.RequestStore
	OIDCCodeStore        = oidcstate.CodeStore
)

func NewConfirmationCodeRepo(db outbox.StoragePgsqlClient) (*ConfirmationCodeRepo, error) {
	return confirmationcoderepo.New(db)
}

func MustConfirmationCodeRepo(db outbox.StoragePgsqlClient) *ConfirmationCodeRepo {
	return confirmationcoderepo.Must(db)
}

func NewConfirmationRepo(db outbox.StoragePgsqlClient) (*ConfirmationRepo, error) {
	return confirmationrepo.New(db)
}

func MustConfirmationRepo(db outbox.StoragePgsqlClient) *ConfirmationRepo {
	return confirmationrepo.Must(db)
}

func NewEmailChangeRepo(db outbox.StoragePgsqlClient) (*EmailChangeRepo, error) {
	return emailchangerepo.New(db)
}

func MustEmailChangeRepo(db outbox.StoragePgsqlClient) *EmailChangeRepo {
	return emailchangerepo.Must(db)
}

func NewIdentityLinkRepo(db outbox.StoragePgsqlClient) (*IdentityLinkRepo, error) {
	return identitylinkrepo.New(db)
}

func MustIdentityLinkRepo(db outbox.StoragePgsqlClient) *IdentityLinkRepo {
	return identitylinkrepo.Must(db)
}

func NewOIDCRefreshTokenRepoOptions(
	db outbox.StoragePgsqlClient,
	tx outbox.StoragePgsqlTxManager,
	setters ...OIDCRefreshTokenRepoOptOptionsSetter,
) OIDCRefreshTokenRepoOptions {
	return oidcrefreshtokenrepo.NewOptions(db, tx, setters...)
}

func NewOIDCRefreshTokenRepo(opts OIDCRefreshTokenRepoOptions) (*OIDCRefreshTokenRepo, error) {
	return oidcrefreshtokenrepo.New(opts)
}

func MustOIDCRefreshTokenRepo(opts OIDCRefreshTokenRepoOptions) *OIDCRefreshTokenRepo {
	return oidcrefreshtokenrepo.Must(opts)
}

func NewPasswordResetTokenRepo(db outbox.StoragePgsqlClient) (*PasswordResetTokenRepo, error) {
	return passwordresettokenrepo.New(db)
}

func MustPasswordResetTokenRepo(db outbox.StoragePgsqlClient) *PasswordResetTokenRepo {
	return passwordresettokenrepo.Must(db)
}

func NewRefreshTokenRepo(db outbox.StoragePgsqlClient) (*RefreshTokenRepo, error) {
	return refreshtokenrepo.New(db)
}

func MustRefreshTokenRepo(db outbox.StoragePgsqlClient) *RefreshTokenRepo {
	return refreshtokenrepo.Must(db)
}

func NewSessionRepo(db outbox.StoragePgsqlClient) (*SessionRepo, error) {
	return sessionrepo.New(db)
}

func MustSessionRepo(db outbox.StoragePgsqlClient) *SessionRepo {
	return sessionrepo.Must(db)
}

func NewSubjectRepo(db outbox.StoragePgsqlClient, tx outbox.StoragePgsqlTxManager) (*SubjectRepo, error) {
	return subjectrepo.New(db, tx)
}

func MustSubjectRepo(db outbox.StoragePgsqlClient, tx outbox.StoragePgsqlTxManager) *SubjectRepo {
	return subjectrepo.Must(db, tx)
}

func NewOIDCRequestStore(client OIDCStateRedisClient, prefix string) *OIDCRequestStore {
	return oidcstate.NewRequestStore(client, prefix)
}

func NewOIDCCodeStore(client OIDCStateRedisClient, prefix string) *OIDCCodeStore {
	return oidcstate.NewCodeStore(client, prefix)
}
