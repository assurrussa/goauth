# Host-scoped verified email changes

The existing RequestEmailChange, PendingEmailChange, and ConfirmEmailChange APIs
retain their primary-email behavior in the empty scope. A trusted host may
register a separately versioned address projection through Config.EmailChangeTargets
and select that fixed scope with WithEmailChangeScope. Never select a scope from
request form, URL, or untrusted claims. Unknown scopes and stores without the
explicit ScopedEmailChangeStore capability fail closed.

The host authorizes the authenticated subject and requires fresh password and,
when enabled, factor proof before requesting the change. A six-digit email code
is entered in the authenticated account page. Confirmation may use another live
session of the same subject; the target and security version must still match.
The old address remains active until the verified change commits.

A target reads and writes only its own projection using the exact managed auth
transaction. Its monotonic version prevents change-away-and-back replay. Apply
must CAS the complete snapshot and atomically invalidate additional host sessions
and pending authority. It must not change primary email, subject, credentials,
realm, external identity links, grants, or issue sessions. A borrowed PostgreSQL
Runtime's SQLExecutor rejects a foreign transaction handle.

Schema 11 extends auth_email_change_records after required-MFA schema 10. It does
not create another challenge or queue subsystem. HMAC binds the host scope,
subject, request ID, security version, old target snapshot, new recipient, and
code. Default primary-email HMAC remains unchanged. Scope metadata is encrypted
with the notification and revalidated against the persisted record and live
host target under the subject lock through the bounded sender call.

Requests retain the subject-wide one-minute resend delay, five-per-hour and
ten-per-day send quota across all scopes. Each record permits five verification
attempts. This is not an additional subject-wide guess budget. Resend consumes
the old record in the same scope and is subject to the shared send quota;
password/security changes invalidate records in every scope. Wrong-code attempts
commit even when the Runtime returns a typed denial. Hosts that own an outer
transaction must preserve that logical-denial commit behavior.

Confirmed change consumes the record, advances canonical security version,
revokes generic sessions/refresh families, applies the host projection, audits,
and queues the old-address notice in one transaction. No result is successful
before the outer owned transaction commits. Unknown commit outcomes require
checking account state rather than blind resubmission. Queue acceptance does
not establish delivery.
