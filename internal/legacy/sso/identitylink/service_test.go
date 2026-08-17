package identitylink_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authcore "github.com/assurrussa/goauth/internal/legacy/core"
	"github.com/assurrussa/goauth/internal/legacy/sso"
	"github.com/assurrussa/goauth/internal/legacy/sso/identitylink"
)

func TestService_LinkAndResolve(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.April, 17, 12, 0, 0, 0, time.UTC)
	subjectID := authcore.MustParseSubjectIDString("123e4567-e89b-12d3-a456-426614174010")
	lookup := &stubSubjectLookup{
		items: map[authcore.SubjectID]authcore.Subject{
			subjectID: {
				ID:    subjectID,
				Kind:  authcore.SubjectKindUser,
				Email: "user@example.com",
				Roles: []string{"member"},
			},
		},
	}
	store := &stubLinkStore{}
	service, err := identitylink.New(store, lookup, func() time.Time { return now })
	require.NoError(t, err)

	emailVerified := true
	link, err := service.LinkSubject(context.Background(), sso.ExternalIdentity{
		Issuer:        "https://zitadel.example.com",
		Subject:       "ext-user-1",
		Email:         "user@example.com",
		EmailVerified: &emailVerified,
	}, lookup.items[subjectID], sso.AuthSourceZitadel)
	require.NoError(t, err)
	require.Equal(t, subjectID, link.SubjectID)
	require.Equal(t, sso.AuthSourceZitadel, link.AuthSource)

	subject, resolvedLink, err := service.ResolveSubject(context.Background(), "https://zitadel.example.com", "ext-user-1")
	require.NoError(t, err)
	require.Equal(t, subjectID.String(), subject.CanonicalID())
	require.Equal(t, link.SubjectID, resolvedLink.SubjectID)

	profile, err := service.Profile(context.Background(), "https://zitadel.example.com", "ext-user-1")
	require.NoError(t, err)
	require.Equal(t, subjectID.String(), profile.SubjectID)
	require.Equal(t, authcore.SubjectKindUser, profile.SubjectKind)
	require.Equal(t, "user@example.com", profile.Email)
	require.True(t, profile.EmailVerified)
	require.Equal(t, sso.AuthSourceZitadel, profile.AuthSource)
	require.Equal(t, []string{"member"}, profile.Roles)
}

func TestService_ResolveNotFound(t *testing.T) {
	t.Parallel()

	service, err := identitylink.New(&stubLinkStore{}, &stubSubjectLookup{}, time.Now)
	require.NoError(t, err)

	_, _, err = service.ResolveSubject(context.Background(), "https://zitadel.example.com", "missing")
	require.ErrorIs(t, err, sso.ErrIdentityLinkNotFound)
}

type stubLinkStore struct {
	items map[string]sso.IdentityLink
}

func (s *stubLinkStore) GetByExternalSubject(_ context.Context, issuer, externalSub string) (sso.IdentityLink, error) {
	if s.items == nil {
		return sso.IdentityLink{}, sso.ErrIdentityLinkNotFound
	}
	link, ok := s.items[issuer+"|"+externalSub]
	if !ok {
		return sso.IdentityLink{}, sso.ErrIdentityLinkNotFound
	}
	return link, nil
}

func (s *stubLinkStore) ListBySubject(_ context.Context, subjectID authcore.SubjectID) ([]sso.IdentityLink, error) {
	if s.items == nil {
		return nil, nil
	}
	result := make([]sso.IdentityLink, 0, len(s.items))
	for _, link := range s.items {
		if link.SubjectID == subjectID {
			result = append(result, link)
		}
	}
	return result, nil
}

func (s *stubLinkStore) Upsert(_ context.Context, link sso.IdentityLink) error {
	if s.items == nil {
		s.items = make(map[string]sso.IdentityLink)
	}
	key := link.Issuer + "|" + link.ExternalSub
	if existing, ok := s.items[key]; ok {
		link.CreatedAt = existing.CreatedAt
	}
	s.items[key] = link
	return nil
}

func (s *stubLinkStore) Delete(_ context.Context, _ authcore.SubjectID, issuer, externalSub string) error {
	if s.items == nil {
		return nil
	}
	delete(s.items, issuer+"|"+externalSub)
	return nil
}

type stubSubjectLookup struct {
	items map[authcore.SubjectID]authcore.Subject
}

func (s *stubSubjectLookup) GetByID(_ context.Context, subjectID authcore.SubjectID) (authcore.Subject, error) {
	if s.items == nil {
		return authcore.Subject{}, nil
	}
	return s.items[subjectID], nil
}
