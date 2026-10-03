# Credential verification admission

`Config.CredentialVerificationRateLimit` applies only to `Runtime.VerifyCredential`
and wrappers that call it, including PostgreSQL `PrepareCredential`.
The zero policy inherits the resolved `LoginRateLimit`, preserving the existing
default of ten attempts per fifteen minutes and existing customized login limits.
An explicit policy uses the existing bounds: positive limit at most 10,000 and
window between one second and twenty-four hours. Partial/invalid policies fail
Runtime construction. There is no disabled or request-controlled bypass mode.

Every attempt, including success, consumes the durable `credential_verify` bucket
keyed by the normalized identifier. Existing bucket identity and storage semantics
are unchanged. Browser `Login`, password-change reauthentication and recovery keep
their previous distinct actions and configured policies. Raising credential
verification admission does not raise their limits.

The shared Runtime password-hash concurrency budget is unchanged. Prefer one
Runtime for browser and per-request verification where possible; separate Runtime
instances have separate budgets, so a host must otherwise bound their aggregate
resource use explicitly. This setting does not cache password matches or authorize
any project, client or account by itself.

A host implementing Basic verification on every request must explicitly choose a
bounded rate appropriate for that traffic and still enforce project/client ingress
admission, request limits, timeouts and the hash budget. This setting alone does
not make an authentication service a per-request Basic authority. Do not raise
all authentication limits or skip canonical subject/project revalidation.

No schema change, token behavior, client secret, production setting or deployment
is part of this additive API. Existing consumers that omit the field retain their
prior behavior.
