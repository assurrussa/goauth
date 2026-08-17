package oidc

import (
	"errors"
	"fmt"
	"time"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/sso"
	embeddedoidc "github.com/assurrussa/goauth/internal/legacy/sso/embeddedoidc"
	externalidentityservice "github.com/assurrussa/goauth/internal/legacy/sso/externalidentity"
	identitylinkservice "github.com/assurrussa/goauth/internal/legacy/sso/identitylink"
	baseoidc "github.com/assurrussa/goauth/oidc"
	oidcprovider "github.com/assurrussa/goauth/oidc/provider"
	oidcverifier "github.com/assurrussa/goauth/oidc/verifier"
)

type (
	EmbeddedProviderOptions = oidcprovider.Options
	VerifierOptions         = oidcverifier.Options
)

type LinkingOptions struct {
	Links             sso.LinkStore
	Subjects          authcore.SubjectLookup
	Reader            authcore.SubjectReader
	Writer            authcore.SubjectWriter
	Hasher            authcore.PasswordHasher
	Tx                authcore.TxManager
	Source            sso.AuthSource
	Now               func() time.Time
	PasswordGenerator func() (string, error)
}

type Options struct {
	Embedded *EmbeddedProviderOptions
	Verifier *VerifierOptions
	Linking  *LinkingOptions
}

type Linking struct {
	IdentityLinks      *identitylinkservice.Service
	ExternalIdentities *externalidentityservice.Service
}

type Kit struct {
	Provider           *oidcprovider.Service
	EmbeddedProvider   sso.Provider
	Verifier           *oidcverifier.Service
	IdentityLinks      *identitylinkservice.Service
	ExternalIdentities *externalidentityservice.Service
}

func NewLinking(opts LinkingOptions) (*Linking, error) {
	switch {
	case opts.Links == nil:
		return nil, errors.New("oidc integration: link store is required")
	case opts.Subjects == nil:
		return nil, errors.New("oidc integration: subject lookup is required")
	case opts.Reader == nil:
		return nil, errors.New("oidc integration: subject reader is required")
	case opts.Writer == nil:
		return nil, errors.New("oidc integration: subject writer is required")
	case opts.Hasher == nil:
		return nil, errors.New("oidc integration: hasher is required")
	}

	linkService, err := identitylinkservice.New(opts.Links, opts.Subjects, opts.Now)
	if err != nil {
		return nil, fmt.Errorf("oidc integration: build identity link service: %w", err)
	}

	externalIdentityService, err := externalidentityservice.New(externalidentityservice.Options{
		Reader:            opts.Reader,
		Writer:            opts.Writer,
		Links:             linkService,
		Hasher:            opts.Hasher,
		Tx:                opts.Tx,
		Source:            opts.Source,
		Now:               opts.Now,
		PasswordGenerator: opts.PasswordGenerator,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc integration: build external identity service: %w", err)
	}

	return &Linking{
		IdentityLinks:      linkService,
		ExternalIdentities: externalIdentityService,
	}, nil
}

func New(opts Options) (*Kit, error) {
	kit := &Kit{
		EmbeddedProvider: embeddedoidc.Disabled(),
	}

	if opts.Embedded != nil {
		providerService, err := oidcprovider.New(*opts.Embedded)
		if err != nil {
			return nil, fmt.Errorf("oidc integration: build embedded provider: %w", err)
		}
		kit.Provider = providerService
		kit.EmbeddedProvider = embeddedoidc.New(providerService)
	}

	if opts.Verifier != nil {
		verifierService, err := oidcverifier.New(*opts.Verifier)
		if err != nil {
			return nil, fmt.Errorf("oidc integration: build verifier: %w", err)
		}
		kit.Verifier = verifierService
	}

	if opts.Linking != nil {
		linking, err := NewLinking(*opts.Linking)
		if err != nil {
			return nil, err
		}
		kit.IdentityLinks = linking.IdentityLinks
		kit.ExternalIdentities = linking.ExternalIdentities
	}

	return kit, nil
}

var _ = baseoidc.Client{}
