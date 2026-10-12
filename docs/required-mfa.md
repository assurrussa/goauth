# Required local MFA

The zero value and `MFAModeOptional` preserve optional enrollment. Set the
trusted runtime `Config.MFAMode` to `MFAModeRequired` to require a local factor.
Required mode rejects missing persistent MFA keys, missing transactional
enrollment/admission storage and unknown policy values at construction. Browser
requests cannot change this policy.

## Password to setup to session

`BeginLocalLogin` returns a pending challenge of kind `factor` or `enrollment`,
or the existing final login for an unenrolled optional account. A pending ID is a
non-authorizing selector, bound to independent host browser state, canonical
subject, realm, security version, factor revision and its original absolute
three-minute password-proof deadline.

For enrollment, use a CSRF-protected POST to `BeginLocalLoginEnrollment`. Its
`MFAEnrollment` contains the setup secret/URL and ten recovery codes. Show the
codes before final TOTP confirmation; they are inactive until that exact setup
is confirmed. Store neither secret nor codes in browser session state, history
props, logs or caches. Repeating setup replaces its ID and encrypted material;
previous setup IDs/codes cannot be confirmed.

`CompleteLocalLoginEnrollment` accepts pending ID, exact enrollment ID, browser
binding and one TOTP. It atomically charges the durable factor budget, validates
current authority, activates the setup and its domain-bound recovery digests,
consumes the pending state, revokes previous sessions/security state, advances
security version and creates the new factor-admitted session. There is no full
session, access/refresh token or application grant before confirmation. The
successful result is the existing `LoginResult`; resume the original trusted
host redirect immediately after publication.

The host keeps its existing authoritative browser-flow owner/CAS fence through
setup and completion, and never stores pending state as authenticated authority.
Unknown commit outcomes return no usable result. Do not retry uncertain
completion as though it were a confirmed rollback.

## Existing sessions and external SSO

Schema 10 adds immutable server-written `auth_sessions.mfa_admission` provenance
and setup fields to the existing pending row; it does not rewrite old factor
ciphertext or keys. New factor completion marks `factor`. Only trusted
`LoginExternal` marks `external`. External admission does not require a local
factor; the host remains responsible for verifying the external provider.

Live session authentication and refresh in required mode reject unknown legacy
or password-only admission. Existing rows default to `unknown`: switching an
installation to required mode can force one new login for legacy sessions whose
origin cannot be proven. No client claim or existing external identity link is
used to guess session provenance. Optional mode remains backward compatible.
Verified factor sessions require a currently enabled local factor; external
sessions remain separately admitted. Normal admitted refresh reuses the same
session and requires no new factor code.

Offline `VerifyJWT` remains explicitly offline and cannot enforce policy
changes or revocation before token expiry. Hosts must use
`AuthenticateSession` (or introspected compatibility authentication), as the
standard adapters already do.
