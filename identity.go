package goauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ResolveExternalIdentity accepts only identity claims verified by a trusted
// provider adapter. Never bind unverified client JSON directly to this method.
func (r *Runtime) ResolveExternalIdentity(ctx context.Context, external ExternalIdentity) (Account, error) {
	account, write, err := r.prepareExternalIdentity(ctx, external)
	if err != nil {
		return Account{}, err
	}
	if err := r.authTransaction.InAuthTransaction(ctx, write); err != nil {
		return Account{}, err
	}
	return account, nil
}

func (r *Runtime) allowsAutoLink(issuer string) bool {
	for _, allowed := range r.autoLinkIssuers {
		if allowed == "*" || allowed == issuer {
			return true
		}
	}
	return false
}

func (r *Runtime) prepareExternalIdentity(
	ctx context.Context,
	external ExternalIdentity,
) (Account, func(context.Context) error, error) {
	if external.Issuer == "" || external.Subject == "" {
		return Account{}, nil, ErrInvalidIdentifier
	}
	account, _, err := r.store.ResolveIdentityLink(ctx, external.Issuer, external.Subject)
	if err == nil {
		if account.Subject.Status != SubjectStatusActive {
			return Account{}, nil, ErrAccountUnavailable
		}
		return account, func(context.Context) error { return nil }, nil
	}
	if !errors.Is(err, ErrIdentityLinkNotFound) {
		return Account{}, nil, fmt.Errorf("resolve identity link: %w", err)
	}

	external, normalizedEmail, err := normalizeExternalIdentity(external)
	if err != nil {
		return Account{}, nil, err
	}
	if normalizedEmail == "" {
		return Account{}, nil, ErrInvalidIdentifier
	}

	existing, findErr := r.store.FindAccount(ctx, IdentifierInput{
		Scheme: IdentifierSchemeEmail,
		Value:  normalizedEmail,
	})
	switch {
	case findErr == nil && !existing.IsZero():
		if !external.EmailVerified || !existing.EmailVerified() || !r.allowsAutoLink(external.Issuer) {
			return Account{}, nil, ErrExplicitIdentityLink
		}
		link := newIdentityLink(existing.Subject.ID, external, normalizedEmail, r.now().UTC())
		if existing.Subject.Status != SubjectStatusActive {
			return Account{}, nil, ErrAccountUnavailable
		}
		return existing, func(ctx context.Context) error {
			current, err := r.store.LockAccount(ctx, existing.Subject.ID)
			if err != nil {
				return err
			}
			if current.Subject.Status != SubjectStatusActive ||
				current.Subject.SecurityVersion != existing.Subject.SecurityVersion ||
				!current.EmailVerified() || current.PrimaryEmail.NormalizedValue != normalizedEmail {
				return ErrExplicitIdentityLink
			}
			if _, err := r.store.LinkIdentity(ctx, link); err != nil {
				return fmt.Errorf("auto-link verified identity: %w", err)
			}
			return r.recordAudit(ctx, SecurityEvent{
				Type: SecurityEventIdentityLinked, SubjectID: existing.Subject.ID, At: r.now().UTC(),
				Attributes: map[string]string{"issuer": external.Issuer, "mode": "verified_email"},
			})
		}, nil

	case findErr != nil && !errors.Is(findErr, ErrAccountNotFound):
		return Account{}, nil, fmt.Errorf("find account for external identity: %w", findErr)
	}

	now := r.now().UTC()
	subjectID := NewSubjectID()
	account = Account{
		Subject: Subject{
			ID:              subjectID,
			Status:          SubjectStatusActive,
			SecurityVersion: 1,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		PrimaryEmail: Identifier{
			ID:              uuid.NewString(),
			SubjectID:       subjectID,
			Scheme:          IdentifierSchemeEmail,
			DisplayValue:    strings.TrimSpace(external.Email),
			NormalizedValue: normalizedEmail,
			CreatedAt:       now,
			UpdatedAt:       now,
		},
		Profile: external.Profile,
	}
	if external.EmailVerified {
		verifiedAt := now
		account.PrimaryEmail.VerifiedAt = &verifiedAt
	}
	link := newIdentityLink(subjectID, external, normalizedEmail, now)
	return account, func(ctx context.Context) error {
		_, _, err := r.store.CreateSSOAccount(ctx, SSOAccountRecord{Account: account, Link: link})
		return err
	}, nil
}

type ExternalLoginRequest struct {
	Identity ExternalIdentity
	Realm    Realm
}

// LoginExternal resolves or provisions an SSO-only account and creates a
// realm-bound session. An unverified email can receive only the user realm's
// limited confirmation session.
func (r *Runtime) LoginExternal(ctx context.Context, request ExternalLoginRequest) (LoginResult, error) {
	realm := request.Realm
	if realm == "" {
		realm = RealmUser
	}
	if err := r.validateRealm(realm); err != nil {
		return LoginResult{}, err
	}
	account, write, err := r.prepareExternalIdentity(ctx, request.Identity)
	if err != nil {
		return LoginResult{}, err
	}
	if account.Subject.Status != SubjectStatusActive {
		return LoginResult{}, ErrAccountUnavailable
	}
	scope, err := r.authorizeRealm(ctx, realm, account)
	if err != nil {
		return LoginResult{}, err
	}
	prepared, err := r.prepareSession(ctx, account, realm, scope)
	if err != nil {
		return LoginResult{}, err
	}

	if err := r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		if err := write(ctx); err != nil {
			return err
		}
		return r.store.CreateSession(ctx, prepared.record)
	}); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Account: account, Tokens: prepared.tokens}, nil
}

func (r *Runtime) LinkExternalIdentity(ctx context.Context, auth AuthContext, external ExternalIdentity) (IdentityLink, error) {
	var link IdentityLink
	err := r.authTransaction.InAuthTransaction(ctx, func(ctx context.Context) error {
		var err error
		link, err = r.linkExternalIdentity(ctx, auth, external)
		return err
	})
	if err != nil {
		return IdentityLink{}, err
	}
	return link, nil
}

func (r *Runtime) linkExternalIdentity(
	ctx context.Context,
	auth AuthContext,
	external ExternalIdentity,
) (IdentityLink, error) {
	if auth.SubjectID.IsZero() || auth.SessionID == "" || auth.Scope != SessionScopeAuthenticated {
		return IdentityLink{}, ErrExplicitIdentityLink
	}
	if _, err := r.store.LockAccount(ctx, auth.SubjectID); err != nil {
		return IdentityLink{}, err
	}
	security, err := r.store.IntrospectSession(ctx, auth.SessionID)
	now := r.now().UTC()
	if err != nil || !security.Session.Active(now) ||
		security.SubjectStatus != SubjectStatusActive ||
		security.Session.SubjectID != auth.SubjectID ||
		security.Session.Realm != auth.Realm ||
		security.Session.Scope != SessionScopeAuthenticated ||
		security.Session.SecurityVersion != auth.SecurityVersion ||
		security.CurrentVersion != auth.SecurityVersion ||
		now.Sub(security.Session.CreatedAt) > r.identityLinkAuthMaxAge {
		return IdentityLink{}, ErrExplicitIdentityLink
	}
	external, normalizedEmail, err := normalizeExternalIdentity(external)
	if err != nil {
		return IdentityLink{}, err
	}
	account, err := r.store.GetAccount(ctx, auth.SubjectID)
	if err != nil || account.Subject.Status != SubjectStatusActive {
		return IdentityLink{}, ErrAccountUnavailable
	}
	link, err := r.store.LinkIdentity(
		ctx,
		newIdentityLink(account.Subject.ID, external, normalizedEmail, now),
	)
	if err != nil {
		return IdentityLink{}, fmt.Errorf("link external identity: %w", err)
	}
	if err := r.recordAudit(ctx, SecurityEvent{
		Type:       SecurityEventIdentityLinked,
		SubjectID:  account.Subject.ID,
		Realm:      auth.Realm,
		At:         now,
		Attributes: map[string]string{"issuer": external.Issuer, "mode": "authenticated"},
	}); err != nil {
		return IdentityLink{}, err
	}

	return link, nil
}

func normalizeExternalIdentity(external ExternalIdentity) (ExternalIdentity, string, error) {
	external.Email = strings.TrimSpace(external.Email)
	if external.Issuer == "" || external.Subject == "" {
		return ExternalIdentity{}, "", ErrInvalidIdentifier
	}
	if external.Email == "" {
		return external, "", nil
	}
	normalizedEmail, err := NormalizeEmail(external.Email)
	if err != nil {
		return ExternalIdentity{}, "", err
	}

	return external, normalizedEmail, nil
}

func newIdentityLink(
	subjectID SubjectID,
	external ExternalIdentity,
	normalizedEmail string,
	now time.Time,
) IdentityLink {
	return IdentityLink{
		ID:              uuid.NewString(),
		SubjectID:       subjectID,
		Issuer:          external.Issuer,
		ExternalSubject: external.Subject,
		EmailNormalized: normalizedEmail,
		EmailVerified:   external.EmailVerified,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}
