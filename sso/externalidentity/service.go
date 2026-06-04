package externalidentity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	authcore "github.com/assurrussa/goauth/core"
	"github.com/assurrussa/goauth/sso"
	identitylinkservice "github.com/assurrussa/goauth/sso/identitylink"
)

var (
	ErrInvalidIdentity = errors.New("invalid external identity")
	ErrEmailRequired   = errors.New("external identity email is required")
	ErrEmailConflict   = errors.New("external identity email is already linked to another subject")
)

type linkManager interface {
	ResolveSubject(ctx context.Context, issuer, externalSub string) (authcore.Subject, sso.IdentityLink, error)
	LinkSubject(
		ctx context.Context,
		external sso.ExternalIdentity,
		subject authcore.Subject,
		source sso.AuthSource,
	) (sso.IdentityLink, error)
	ListLinks(ctx context.Context, subjectID authcore.SubjectID) ([]sso.IdentityLink, error)
}

type passwordGenerator func() (string, error)

type Options struct {
	Reader            authcore.SubjectReader
	Writer            authcore.SubjectWriter
	Links             linkManager
	Hasher            authcore.PasswordHasher
	Tx                authcore.TxManager
	Source            sso.AuthSource
	Now               func() time.Time
	PasswordGenerator passwordGenerator
}

type Service struct {
	reader   authcore.SubjectReader
	writer   authcore.SubjectWriter
	links    linkManager
	hasher   authcore.PasswordHasher
	tx       authcore.TxManager
	source   sso.AuthSource
	now      func() time.Time
	password passwordGenerator
}

func New(opts Options) (*Service, error) {
	switch {
	case opts.Reader == nil:
		return nil, errors.New("external identity reader is required")
	case opts.Writer == nil:
		return nil, errors.New("external identity writer is required")
	case opts.Links == nil:
		return nil, errors.New("external identity link manager is required")
	case opts.Hasher == nil:
		return nil, errors.New("external identity hasher is required")
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	password := opts.PasswordGenerator
	if password == nil {
		password = defaultPasswordGenerator
	}

	return &Service{
		reader:   opts.Reader,
		writer:   opts.Writer,
		links:    opts.Links,
		hasher:   opts.Hasher,
		tx:       opts.Tx,
		source:   sso.NormalizeAuthSource(opts.Source),
		now:      now,
		password: password,
	}, nil
}

func (s *Service) Resolve(ctx context.Context, external sso.ExternalIdentity) (authcore.Subject, sso.IdentityProfile, error) {
	normalized, err := normalizeExternalIdentity(external)
	if err != nil {
		return authcore.Subject{}, sso.IdentityProfile{}, err
	}

	subject, link, err := s.links.ResolveSubject(ctx, normalized.Issuer, normalized.Subject)
	if err == nil {
		return subject, sso.BuildIdentityProfile(subject, link), nil
	}
	if !errors.Is(err, sso.ErrIdentityLinkNotFound) {
		return authcore.Subject{}, sso.IdentityProfile{}, fmt.Errorf("resolve external identity link: %w", err)
	}
	if normalized.Email == "" {
		return authcore.Subject{}, sso.IdentityProfile{}, ErrEmailRequired
	}

	var resolved authcore.Subject
	var profile sso.IdentityProfile
	resolveFn := func(ctx context.Context) error {
		subject, err := s.reader.GetByEmail(ctx, normalized.Email)
		if err != nil {
			return fmt.Errorf("lookup local subject by email: %w", err)
		}

		if subject.IsZero() {
			subject, err = s.createShadowUser(ctx, normalized)
			if err != nil {
				return err
			}
		}
		if err := s.ensureIssuerNotConflicting(ctx, subject, normalized); err != nil {
			return err
		}

		link, err := s.links.LinkSubject(ctx, normalized, subject, s.source)
		if err != nil {
			return fmt.Errorf("link local subject: %w", err)
		}

		resolved = subject
		profile = sso.BuildIdentityProfile(subject, link)
		return nil
	}

	if s.tx != nil {
		if err := s.tx.RunInTx(ctx, resolveFn); err != nil {
			return authcore.Subject{}, sso.IdentityProfile{}, err
		}
	} else if err := resolveFn(ctx); err != nil {
		return authcore.Subject{}, sso.IdentityProfile{}, err
	}

	return resolved, profile, nil
}

func (s *Service) ensureIssuerNotConflicting(
	ctx context.Context,
	subject authcore.Subject,
	external sso.ExternalIdentity,
) error {
	links, err := s.links.ListLinks(ctx, subject.AuthSubjectID())
	if err != nil {
		return fmt.Errorf("list subject identity links: %w", err)
	}

	for _, link := range links {
		if !strings.EqualFold(strings.TrimSpace(link.Issuer), external.Issuer) {
			continue
		}
		if strings.TrimSpace(link.ExternalSub) == external.Subject {
			return nil
		}

		return ErrEmailConflict
	}

	return nil
}

func (s *Service) createShadowUser(ctx context.Context, external sso.ExternalIdentity) (authcore.Subject, error) {
	rawPassword, err := s.password()
	if err != nil {
		return authcore.Subject{}, fmt.Errorf("generate shadow password: %w", err)
	}

	hash, err := s.hasher.GenerateHash(rawPassword)
	if err != nil {
		return authcore.Subject{}, fmt.Errorf("hash shadow password: %w", err)
	}

	subject := authcore.Subject{
		Kind:         authcore.SubjectKindUser,
		Email:        external.Email,
		Name:         shadowNameFromEmail(external.Email),
		PasswordHash: string(hash),
	}
	if external.EmailVerified != nil && *external.EmailVerified {
		confirmedAt := s.now().UTC()
		subject.ConfirmedEmailAt = &confirmedAt
	}

	created, err := s.writer.CreateUser(ctx, subject)
	if err == nil {
		return created, nil
	}

	existing, readErr := s.reader.GetByEmail(ctx, external.Email)
	if readErr == nil && !existing.IsZero() {
		return existing, nil
	}

	if readErr != nil {
		return authcore.Subject{}, fmt.Errorf("create shadow user: %w", errors.Join(err, readErr))
	}

	return authcore.Subject{}, fmt.Errorf("create shadow user: %w", err)
}

func normalizeExternalIdentity(external sso.ExternalIdentity) (sso.ExternalIdentity, error) {
	normalized := sso.ExternalIdentity{
		Issuer:  strings.TrimRight(strings.TrimSpace(external.Issuer), "/"),
		Subject: strings.TrimSpace(external.Subject),
		Email:   strings.ToLower(strings.TrimSpace(external.Email)),
	}
	if external.EmailVerified != nil {
		value := *external.EmailVerified
		normalized.EmailVerified = &value
	}

	if normalized.Issuer == "" || normalized.Subject == "" {
		return sso.ExternalIdentity{}, ErrInvalidIdentity
	}

	return normalized, nil
}

func defaultPasswordGenerator() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return "sso-shadow:" + base64.RawURLEncoding.EncodeToString(buf), nil
}

func shadowNameFromEmail(email string) string {
	local, _, ok := strings.Cut(email, "@")
	if !ok {
		return email
	}

	local = strings.TrimSpace(local)
	if local == "" {
		return email
	}

	return local
}

var _ linkManager = (*identitylinkservice.Service)(nil)
