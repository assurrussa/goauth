package identitylink

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	authcore "github.com/assurrussa/goauth/core"
	"github.com/assurrussa/goauth/sso"
)

type Service struct {
	links    sso.LinkStore
	subjects authcore.SubjectLookup
	now      func() time.Time
}

func New(links sso.LinkStore, subjects authcore.SubjectLookup, now func() time.Time) (*Service, error) {
	switch {
	case links == nil:
		return nil, errors.New("identity link store is required")
	case subjects == nil:
		return nil, errors.New("subject lookup is required")
	}
	if now == nil {
		now = time.Now
	}

	return &Service{
		links:    links,
		subjects: subjects,
		now:      now,
	}, nil
}

func (s *Service) ResolveSubject(
	ctx context.Context,
	issuer string,
	externalSub string,
) (authcore.Subject, sso.IdentityLink, error) {
	link, err := s.links.GetByExternalSubject(ctx, issuer, externalSub)
	if err != nil {
		return authcore.Subject{}, sso.IdentityLink{}, err
	}

	subject, err := s.subjects.GetByID(ctx, link.SubjectID)
	if err != nil {
		return authcore.Subject{}, sso.IdentityLink{}, fmt.Errorf("resolve linked subject: %w", err)
	}

	return subject, link, nil
}

func (s *Service) LinkSubject(
	ctx context.Context,
	external sso.ExternalIdentity,
	subject authcore.Subject,
	source sso.AuthSource,
) (sso.IdentityLink, error) {
	if subject.IsZero() {
		return sso.IdentityLink{}, errors.New("subject is required")
	}

	issuer := strings.TrimSpace(external.Issuer)
	externalSub := strings.TrimSpace(external.Subject)
	if issuer == "" || externalSub == "" {
		return sso.IdentityLink{}, errors.New("issuer and external subject are required")
	}

	subjectID := subject.AuthSubjectID()
	now := s.now().UTC()
	link := sso.IdentityLink{
		SubjectID:     subjectID,
		SubjectKind:   subject.Kind,
		Issuer:        issuer,
		ExternalSub:   externalSub,
		AuthSource:    sso.NormalizeAuthSource(source),
		Email:         strings.TrimSpace(external.Email),
		EmailVerified: external.EmailVerified,
		LastSeenAt:    now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.links.Upsert(ctx, link); err != nil {
		return sso.IdentityLink{}, fmt.Errorf("upsert identity link: %w", err)
	}

	return link, nil
}

func (s *Service) Profile(
	ctx context.Context,
	issuer string,
	externalSub string,
) (sso.IdentityProfile, error) {
	subject, link, err := s.ResolveSubject(ctx, issuer, externalSub)
	if err != nil {
		return sso.IdentityProfile{}, err
	}

	return sso.BuildIdentityProfile(subject, link), nil
}

func (s *Service) ListLinks(ctx context.Context, subjectID authcore.SubjectID) ([]sso.IdentityLink, error) {
	if subjectID.IsZero() {
		return nil, errors.New("subject id is required")
	}

	links, err := s.links.ListBySubject(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("list identity links: %w", err)
	}

	return links, nil
}
