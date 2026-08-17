package externalidentity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/sso"
	externalidentityservice "github.com/assurrussa/goauth/internal/legacy/sso/externalidentity"
)

func TestResolveExistingLink(t *testing.T) {
	now := time.Date(2026, time.April, 17, 12, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174020")
	subject := authcore.Subject{
		ID:    subjectID,
		Kind:  authcore.SubjectKindUser,
		Email: "linked@example.com", //nolint:goconst // autofix
	}
	verified := true

	links := &linkManagerFake{
		byExternal: map[string]linkResolution{
			"https://zitadel.example.com|ext-1": {
				subject: subject,
				link: sso.IdentityLink{
					SubjectID:     subject.AuthSubjectID(),
					SubjectKind:   authcore.SubjectKindUser,
					Issuer:        "https://zitadel.example.com", //nolint:goconst // autofix
					ExternalSub:   "ext-1",
					AuthSource:    sso.AuthSourceZitadel,
					Email:         "linked@example.com",
					EmailVerified: &verified,
				},
			},
		},
	}

	svc, err := externalidentityservice.New(externalidentityservice.Options{
		Reader: readerFake{},
		Writer: &writerFake{},
		Links:  links,
		Hasher: hasherFake{},
		Source: sso.AuthSourceZitadel,
		Now:    func() time.Time { return now },
	})
	require.NoError(t, err)

	resolved, profile, err := svc.Resolve(context.Background(), sso.ExternalIdentity{
		Issuer:        "https://zitadel.example.com",
		Subject:       "ext-1",
		Email:         "linked@example.com",
		EmailVerified: &verified,
	})
	require.NoError(t, err)
	require.Equal(t, subject.CanonicalID(), resolved.CanonicalID())
	require.Equal(t, subject.CanonicalID(), profile.SubjectID)
	require.True(t, profile.EmailVerified)
}

func TestResolveLinksExistingLocalUserByEmail(t *testing.T) {
	now := time.Date(2026, time.April, 17, 12, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174021")
	subject := authcore.Subject{
		ID:               subjectID,
		Kind:             authcore.SubjectKindUser,
		Email:            "user@example.com", //nolint:goconst // autofix
		ConfirmedEmailAt: &now,
	}
	verified := true
	links := &linkManagerFake{}

	svc, err := externalidentityservice.New(externalidentityservice.Options{
		Reader: readerFake{
			items: map[string]authcore.Subject{
				"user@example.com": subject,
			},
		},
		Writer: &writerFake{},
		Links:  links,
		Hasher: hasherFake{},
		Source: sso.AuthSourceZitadel,
		Now:    func() time.Time { return now },
	})
	require.NoError(t, err)

	resolved, profile, err := svc.Resolve(context.Background(), sso.ExternalIdentity{
		Issuer:        "https://zitadel.example.com/",
		Subject:       "ext-2",
		Email:         "User@example.com",
		EmailVerified: &verified,
	})
	require.NoError(t, err)
	require.Equal(t, subject.CanonicalID(), resolved.CanonicalID())
	require.Equal(t, subject.AuthSubjectID(), links.upserts[0].SubjectID)
	require.Equal(t, "https://zitadel.example.com", links.upserts[0].Issuer)
	require.Equal(t, "user@example.com", profile.Email)
	require.True(t, profile.EmailVerified)
}

func TestResolveRequiresExplicitLinkForUnverifiedExistingEmail(t *testing.T) {
	verified := true
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174026")
	subject := authcore.Subject{
		ID:    subjectID,
		Kind:  authcore.SubjectKindUser,
		Email: "unverified-local@example.com",
	}
	links := &linkManagerFake{}
	svc, err := externalidentityservice.New(externalidentityservice.Options{
		Reader: readerFake{items: map[string]authcore.Subject{subject.Email: subject}},
		Writer: &writerFake{},
		Links:  links,
		Hasher: hasherFake{},
		Source: sso.AuthSourceZitadel,
	})
	require.NoError(t, err)

	_, _, err = svc.Resolve(context.Background(), sso.ExternalIdentity{
		Issuer:        "https://zitadel.example.com",
		Subject:       "external-unverified-local",
		Email:         subject.Email,
		EmailVerified: &verified,
	})
	require.ErrorIs(t, err, externalidentityservice.ErrExplicitLinkRequired)
	require.Empty(t, links.upserts)
}

func TestResolveCreatesShadowUser(t *testing.T) {
	now := time.Date(2026, time.April, 17, 12, 0, 0, 0, time.UTC)
	verified := true
	shadowID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174022")
	writer := &writerFake{
		createResult: authcore.Subject{
			ID:    shadowID,
			Kind:  authcore.SubjectKindUser,
			Email: "shadow@example.com",
		},
	}
	links := &linkManagerFake{}

	svc, err := externalidentityservice.New(externalidentityservice.Options{
		Reader: readerFake{},
		Writer: writer,
		Links:  links,
		Hasher: hasherFake{},
		Source: sso.AuthSourceZitadel,
		Now:    func() time.Time { return now },
		PasswordGenerator: func() (string, error) {
			return "shadow-secret", nil
		},
	})
	require.NoError(t, err)

	resolved, profile, err := svc.Resolve(context.Background(), sso.ExternalIdentity{
		Issuer:        "https://zitadel.example.com",
		Subject:       "ext-new",
		Email:         "shadow@example.com",
		EmailVerified: &verified,
	})
	require.NoError(t, err)
	require.Equal(t, shadowID.String(), resolved.CanonicalID())
	require.NotNil(t, writer.created.ConfirmedEmailAt)
	require.Empty(t, writer.created.PasswordHash)
	require.Equal(t, sso.AuthSourceZitadel, profile.AuthSource)
}

func TestResolveCreatesShadowUserWithoutConfirmedEmailWhenUnverified(t *testing.T) {
	now := time.Date(2026, time.April, 17, 12, 0, 0, 0, time.UTC)
	verified := false
	shadowID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174023")
	writer := &writerFake{
		createResult: authcore.Subject{
			ID:    shadowID,
			Kind:  authcore.SubjectKindUser,
			Email: "shadow-unverified@example.com",
		},
	}

	svc, err := externalidentityservice.New(externalidentityservice.Options{
		Reader: readerFake{},
		Writer: writer,
		Links:  &linkManagerFake{},
		Hasher: hasherFake{},
		Source: sso.AuthSourceZitadel,
		Now:    func() time.Time { return now },
		PasswordGenerator: func() (string, error) {
			return "shadow-secret", nil
		},
	})
	require.NoError(t, err)

	resolved, profile, err := svc.Resolve(context.Background(), sso.ExternalIdentity{
		Issuer:        "https://zitadel.example.com",
		Subject:       "ext-new-unverified",
		Email:         "shadow-unverified@example.com",
		EmailVerified: &verified,
	})
	require.NoError(t, err)
	require.Equal(t, shadowID.String(), resolved.CanonicalID())
	require.Nil(t, writer.created.ConfirmedEmailAt)
	require.Empty(t, writer.created.PasswordHash)
	require.False(t, profile.EmailVerified)
}

func TestResolveRejectsIssuerConflictForSameEmail(t *testing.T) {
	now := time.Date(2026, time.April, 17, 12, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174024")
	subject := authcore.Subject{
		ID:               subjectID,
		Kind:             authcore.SubjectKindUser,
		Email:            "user@example.com",
		ConfirmedEmailAt: &now,
	}
	verified := true
	links := &linkManagerFake{
		bySubject: map[string][]sso.IdentityLink{
			subject.CanonicalID(): {
				{
					SubjectID:   subject.AuthSubjectID(),
					SubjectKind: authcore.SubjectKindUser,
					Issuer:      "https://zitadel.example.com",
					ExternalSub: "another-subject",
				},
			},
		},
	}

	svc, err := externalidentityservice.New(externalidentityservice.Options{
		Reader: readerFake{
			items: map[string]authcore.Subject{"user@example.com": subject},
		},
		Writer: &writerFake{},
		Links:  links,
		Hasher: hasherFake{},
		Source: sso.AuthSourceZitadel,
	})
	require.NoError(t, err)

	_, _, err = svc.Resolve(context.Background(), sso.ExternalIdentity{
		Issuer:        "https://zitadel.example.com",
		Subject:       "ext-conflict",
		Email:         "user@example.com",
		EmailVerified: &verified,
	})
	require.ErrorIs(t, err, externalidentityservice.ErrEmailConflict)
}

func TestResolveRejectsCreateRaceWhenExistingUserHasConflictingIssuerLink(t *testing.T) {
	now := time.Date(2026, time.April, 17, 12, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174025")
	subject := authcore.Subject{
		ID:               subjectID,
		Kind:             authcore.SubjectKindUser,
		Email:            "race@example.com", //nolint:goconst // autofix
		ConfirmedEmailAt: &now,
	}
	verified := true
	reader := &readerSequenceFake{
		results: []authcore.Subject{
			{},
			subject,
		},
	}
	links := &linkManagerFake{
		bySubject: map[string][]sso.IdentityLink{
			subject.CanonicalID(): {
				{
					SubjectID:   subject.AuthSubjectID(),
					SubjectKind: authcore.SubjectKindUser,
					Issuer:      "https://zitadel.example.com",
					ExternalSub: "existing-subject",
				},
			},
		},
	}
	svc, err := externalidentityservice.New(externalidentityservice.Options{
		Reader: reader,
		Writer: &writerFake{createErr: errors.New("duplicate key")},
		Links:  links,
		Hasher: hasherFake{},
		Source: sso.AuthSourceZitadel,
	})
	require.NoError(t, err)

	_, _, err = svc.Resolve(context.Background(), sso.ExternalIdentity{
		Issuer:        "https://zitadel.example.com",
		Subject:       "ext-race",
		Email:         "race@example.com",
		EmailVerified: &verified,
	})
	require.ErrorIs(t, err, externalidentityservice.ErrEmailConflict)
	require.Empty(t, links.upserts)
}

func TestResolveRequiresEmailWhenLinkIsMissing(t *testing.T) {
	svc, err := externalidentityservice.New(externalidentityservice.Options{
		Reader: readerFake{},
		Writer: &writerFake{},
		Links:  &linkManagerFake{},
		Hasher: hasherFake{},
		Source: sso.AuthSourceZitadel,
	})
	require.NoError(t, err)

	_, _, err = svc.Resolve(context.Background(), sso.ExternalIdentity{
		Issuer:  "https://zitadel.example.com",
		Subject: "ext-missing-email",
	})
	require.ErrorIs(t, err, externalidentityservice.ErrEmailRequired)
}

type readerFake struct {
	items map[string]authcore.Subject
	err   error
}

func (f readerFake) GetByEmail(_ context.Context, email string) (authcore.Subject, error) {
	if f.err != nil {
		return authcore.Subject{}, f.err
	}

	return f.items[email], nil
}

type readerSequenceFake struct {
	results []authcore.Subject
	errs    []error
	calls   int
}

func (f *readerSequenceFake) GetByEmail(_ context.Context, _ string) (authcore.Subject, error) {
	call := f.calls
	f.calls++

	if call < len(f.errs) && f.errs[call] != nil {
		return authcore.Subject{}, f.errs[call]
	}
	if call < len(f.results) {
		return f.results[call], nil
	}

	return authcore.Subject{}, nil
}

type writerFake struct {
	createResult authcore.Subject
	createErr    error
	created      authcore.Subject
}

func (f *writerFake) CreateUser(_ context.Context, subject authcore.Subject) (authcore.Subject, error) {
	if f.createErr != nil {
		return authcore.Subject{}, f.createErr
	}
	f.created = subject
	if !f.createResult.IsZero() {
		return f.createResult, nil
	}

	subject.ID = authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174026")
	return subject, nil
}

func (f *writerFake) UpdatePassword(context.Context, authcore.Subject, string) error {
	return nil
}

type hasherFake struct{}

func (hasherFake) GenerateHash(password string) ([]byte, error) {
	return []byte("hashed:" + password), nil
}

func (hasherFake) CompareHash(string, string) error {
	return nil
}

type linkResolution struct {
	subject authcore.Subject
	link    sso.IdentityLink
	err     error
}

type linkManagerFake struct {
	byExternal map[string]linkResolution
	bySubject  map[string][]sso.IdentityLink
	upserts    []sso.IdentityLink
}

func (f *linkManagerFake) ResolveSubject(
	_ context.Context,
	issuer,
	externalSub string,
) (authcore.Subject, sso.IdentityLink, error) {
	key := issuer + "|" + externalSub
	if f.byExternal != nil {
		if resolved, ok := f.byExternal[key]; ok {
			if resolved.err != nil {
				return authcore.Subject{}, sso.IdentityLink{}, resolved.err
			}
			return resolved.subject, resolved.link, nil
		}
	}

	return authcore.Subject{}, sso.IdentityLink{}, sso.ErrIdentityLinkNotFound
}

func (f *linkManagerFake) LinkSubject(
	_ context.Context,
	external sso.ExternalIdentity,
	subject authcore.Subject,
	source sso.AuthSource,
) (sso.IdentityLink, error) {
	link := sso.IdentityLink{
		SubjectID:     subject.AuthSubjectID(),
		SubjectKind:   subject.Kind,
		Issuer:        external.Issuer,
		ExternalSub:   external.Subject,
		AuthSource:    source,
		Email:         external.Email,
		EmailVerified: external.EmailVerified,
	}
	f.upserts = append(f.upserts, link)
	return link, nil
}

func (f *linkManagerFake) ListLinks(_ context.Context, subjectID authcore.SubjectID) ([]sso.IdentityLink, error) {
	return append([]sso.IdentityLink(nil), f.bySubject[subjectID.String()]...), nil
}

func TestResolveFallsBackToLookupAfterCreateRace(t *testing.T) {
	now := time.Date(2026, time.April, 17, 12, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174027")
	subject := authcore.Subject{
		ID:               subjectID,
		Kind:             authcore.SubjectKindUser,
		Email:            "race@example.com",
		ConfirmedEmailAt: &now,
	}
	verified := true
	reader := readerFake{
		items: map[string]authcore.Subject{"race@example.com": subject},
	}
	svc, err := externalidentityservice.New(externalidentityservice.Options{
		Reader: reader,
		Writer: &writerFake{createErr: errors.New("duplicate key")},
		Links:  &linkManagerFake{},
		Hasher: hasherFake{},
		Source: sso.AuthSourceZitadel,
	})
	require.NoError(t, err)

	resolved, _, err := svc.Resolve(context.Background(), sso.ExternalIdentity{
		Issuer:        "https://zitadel.example.com",
		Subject:       "ext-race",
		Email:         "race@example.com",
		EmailVerified: &verified,
	})
	require.NoError(t, err)
	require.Equal(t, subject.CanonicalID(), resolved.CanonicalID())
}
