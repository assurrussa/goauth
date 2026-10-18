package goauth

import (
	"context"
)

// ProvisionExternalIdentity resolves an exact existing issuer/subject binding or
// creates a new SSO-only account. Unlike ResolveExternalIdentity, it NEVER links
// by email, regardless of AutoLinkVerifiedEmailIssuers. Email collisions require
// the separate authenticated explicit-link workflow.
//
// This is a trusted host API, not an HTTP signup endpoint. The caller MUST verify
// the provider proof, project admission and enrollment policy before calling it.
// It grants no membership, roles, password or session. Hosts must join this call,
// their enrollment record and mandatory audit in one owned auth transaction,
// and withhold a successful result until the outer commit is confirmed.
func (r *Runtime) ProvisionExternalIdentity(ctx context.Context, external ExternalIdentity) (Account, error) {
	account, write, err := r.prepareExternalIdentityPolicy(ctx, external, false)
	if err != nil {
		return Account{}, err
	}
	if err := r.authTransaction.InAuthTransaction(ctx, write); err != nil {
		return Account{}, err
	}
	return account, nil
}
