# Optional MFA enrollment advisory

Session-bound hosts can populate SessionProjection.MFA with an MFAEnrollment
version 1 snapshot. The provider signs authhub_mfa in profile-scoped ID tokens:

{"version":1,"enrolled":false,"setup_available":true}

The host must obtain enrollment from its canonical enabled factor state under
its existing issuance/refresh subject lock. Setup availability reflects usable
persistent enrollment keys, not a URL from profile metadata. The hint carries
no secrets, factor identifiers, recovery data, or authentication method claim.

This is display-only. It is not amr, acr, an authentication-strength assertion,
a session binding, or an admission policy. Required enrollment remains entirely
at the authority. Missing/unknown-version projections are omitted without
changing login, access-token issuance, or renewal. Both booleans are explicit.

Only normal token issuance and refresh update a relying party's snapshot.
Never add per-request authority polling, extra refreshes, or a first-login
interstitial for this hint. A consumer hides a reminder when the hint is absent,
malformed, unknown-version, enrolled, or setup-unavailable. A valid signed hint
can show a nonblocking account-settings link for an unenrolled account; the
link must come from a configured and validated trusted issuer, never the claim.
