package authjwtservice

import (
	"errors"

	authcore "github.com/assurrussa/goauth/core"
)

type Options struct {
	Reader             authcore.SubjectReader
	Lookup             authcore.SubjectLookup
	Writer             authcore.SubjectWriter
	Tokens             authcore.RefreshTokenStore
	Issuer             authcore.TokenIssuer
	Hasher             authcore.PasswordHasher
	Tx                 authcore.TxManager
	ProfileProvisioner authcore.ProfileProvisioner
	authService        authService
}

type OptOptionsSetter func(o *Options)

func NewOptions(
	reader authcore.SubjectReader,
	lookup authcore.SubjectLookup,
	writer authcore.SubjectWriter,
	tokens authcore.RefreshTokenStore,
	issuer authcore.TokenIssuer,
	hasher authcore.PasswordHasher,
	tx authcore.TxManager,
	options ...OptOptionsSetter,
) Options {
	o := Options{
		Reader: reader,
		Lookup: lookup,
		Writer: writer,
		Tokens: tokens,
		Issuer: issuer,
		Hasher: hasher,
		Tx:     tx,
	}
	for _, opt := range options {
		opt(&o)
	}

	return o
}

func WithAuthService(service authService) OptOptionsSetter {
	return func(o *Options) {
		o.authService = service
	}
}

func WithProfileProvisioner(provisioner authcore.ProfileProvisioner) OptOptionsSetter {
	return func(o *Options) {
		o.ProfileProvisioner = provisioner
	}
}

func (o Options) Validate() error {
	var errs []error
	if o.Reader == nil {
		errs = append(errs, errors.New("reader is required"))
	}
	if o.Lookup == nil {
		errs = append(errs, errors.New("lookup is required"))
	}
	if o.Writer == nil {
		errs = append(errs, errors.New("writer is required"))
	}
	if o.Tokens == nil {
		errs = append(errs, errors.New("tokens are required"))
	}
	if o.Issuer == nil {
		errs = append(errs, errors.New("issuer is required"))
	}
	if o.Hasher == nil {
		errs = append(errs, errors.New("hasher is required"))
	}
	if o.Tx == nil {
		errs = append(errs, errors.New("tx is required"))
	}
	return errors.Join(errs...)
}
