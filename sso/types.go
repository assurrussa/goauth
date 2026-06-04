package sso

import (
	"maps"
	"slices"
	"strings"
	"time"

	authcore "github.com/assurrussa/goauth/core"
)

type ProviderKind string

const (
	ProviderKindEmbeddedOIDC ProviderKind = "embedded_oidc"
	ProviderKindZitadel      ProviderKind = "zitadel"
	ProviderKindAuthentik    ProviderKind = "authentik"
)

type AuthSource string

const (
	AuthSourceEmbeddedOIDC AuthSource = "embedded_oidc"
	AuthSourceZitadel      AuthSource = "zitadel"
	AuthSourceAuthentik    AuthSource = "authentik"
)

type ExternalIdentity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified *bool
}

type IdentityLink struct {
	SubjectID     authcore.SubjectID
	SubjectKind   authcore.SubjectKind
	Issuer        string
	ExternalSub   string
	AuthSource    AuthSource
	Email         string
	EmailVerified *bool
	LastSeenAt    time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (l IdentityLink) IsZero() bool {
	return l.SubjectID.IsZero() && l.Issuer == "" && l.ExternalSub == ""
}

type IdentityProfile struct {
	SubjectID     string
	SubjectKind   authcore.SubjectKind
	Email         string
	EmailVerified bool
	Roles         []string
	Permissions   map[string][]string
	Issuer        string
	AuthSource    AuthSource
}

func BuildIdentityProfile(subject authcore.Subject, link IdentityLink) IdentityProfile {
	profile := IdentityProfile{
		SubjectID:   subject.CanonicalID(),
		SubjectKind: subject.Kind,
		Email:       subject.Email,
		Roles:       slices.Clone(subject.Roles),
		Issuer:      link.Issuer,
		AuthSource:  NormalizeAuthSource(link.AuthSource),
	}
	if link.Email != "" {
		profile.Email = link.Email
	}
	if subject.ConfirmedEmailAt != nil && !subject.ConfirmedEmailAt.IsZero() {
		profile.EmailVerified = true
	}
	if link.EmailVerified != nil {
		profile.EmailVerified = *link.EmailVerified
	}
	if len(subject.Permissions) != 0 {
		perms := maps.Clone(subject.Permissions)
		for key, values := range perms {
			perms[key] = slices.Clone(values)
		}
		profile.Permissions = perms
	}

	return profile
}

func NormalizeProviderKind(raw string) ProviderKind {
	switch ProviderKind(strings.TrimSpace(strings.ToLower(raw))) {
	case ProviderKindZitadel:
		return ProviderKindZitadel
	case ProviderKindAuthentik:
		return ProviderKindAuthentik
	default:
		return ProviderKindEmbeddedOIDC
	}
}

func NormalizeAuthSource(raw AuthSource) AuthSource {
	switch AuthSource(strings.TrimSpace(strings.ToLower(string(raw)))) {
	case AuthSourceZitadel:
		return AuthSourceZitadel
	case AuthSourceAuthentik:
		return AuthSourceAuthentik
	default:
		return AuthSourceEmbeddedOIDC
	}
}

func AuthSourceForProviderKind(kind ProviderKind) AuthSource {
	switch NormalizeProviderKind(string(kind)) {
	case ProviderKindZitadel:
		return AuthSourceZitadel
	case ProviderKindAuthentik:
		return AuthSourceAuthentik
	default:
		return AuthSourceEmbeddedOIDC
	}
}
