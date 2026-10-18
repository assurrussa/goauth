# Strict external provisioning

ProvisionExternalIdentity is an explicit trusted-host API for an opt-in enrollment policy. It accepts only provider-verified exact issuer/subject and resolves an existing active binding or creates a canonical SSO-only account. It never automatically links an existing email, even when the general auto-link policy allows it. A new account requires an email; the existing admin realm still requires verified email and host membership.

The caller must verify project access and invitation/pending policy before invoking this method. It creates no local credential, role, membership or session. Join provisioning, the application's enrollment record and audit in the same owned auth transaction. Do not publish results until the outer commit is confirmed; unknown outcomes remain errors. Concurrent identifier conflicts do not authorize linking or automatically retry a secret-bearing operation.

ResolveExternalIdentity and LoginExternal retain their existing compatibility behavior. Existing local accounts must use the authenticated explicit-link flow; this new method does not bypass it.

Candidate tests cover verified email collision, credential absence, exact repeated binding and invalid identity. PostgreSQL enrollment/rollback/concurrency coverage belongs to the consuming GoAdmin component as well. This document does not establish completed tests or a published release.
