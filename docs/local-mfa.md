# Optional local multi-factor authentication

Configure Config.MFAKeys with a durable encryption key ring, distinct from signing, token-HMAC and notification keys. Enrollment is optional. PostgreSQL schema version 9 adds local factor, recovery, attempt, login-continuation and enrollment tables. Existing central AuthHub factors remain in their original tables.

The PostgreSQL admission store is always active, even without configured MFA keys. An enrolled subject cannot obtain password-only tokens through Login or prepared local-session issuance. Missing encryption keys fail closed. Existing custom stores may omit MFA admission only if they cannot contain enrolled factors; configured MFA requires the full transactional capability and owned transactions.

## Login

BeginLocalLogin verifies the password and returns either LoginResult or a pending challenge selector with fixed expiry. CompleteLocalLogin checks the factor and consumes the pending challenge in the same owned transaction as session creation and audit. The binding is a digest of independent, random, server-managed browser state. A pending selector grants no authority and must never be stored as an authenticated session.

The host must enforce an authoritative browser-flow publication fence across all concurrent password and factor submissions, including different subjects. Persist the currently selected challenge and a non-reclaimable operation owner with versioned compare-and-swap; publish tokens only after terminal CAS. Pin the resulting canonical session ID and check that pin on authenticated reads so stale response cookies cannot revive a cancelled flow. Revoke a provisional result if publication or browser-session persistence fails.

Existing authenticated sessions and refresh operations do not ask for another factor. Verified external SSO admission remains separate. Credential verification/preparation proves only the password, not MFA.

Expected wrong-factor outcomes commit their durable attempt count. PostgreSQL limits each subject to ten factor attempts per five-minute database-clock window, shared across login and management. ErrMFALoginDenied means no usable result is returned; it does not prove no session was committed, especially if expiry is crossed just after commit. ErrOperationOutcomeUnknown takes precedence and must not trigger a blind retry or release an ambiguous browser-flow fence.

## Enrollment and management

MFAStatus accepts an authenticated AuthContext and returns the enrollment state with any management-availability error. Missing MFA keys return ErrMFAUnavailable even for an unenrolled account; an enrolled account still returns true alongside that error. Hosts must check the error before offering enrollment or management actions. BeginMFAEnrollment and ConfirmMFAEnrollment require a live authenticated session, current password and independent browser binding. Replacing an enabled factor also requires its current factor at Begin. Pending enrollment expires after five minutes and is bound to the session, security version and factor revision.

Confirmation consumes the confirming TOTP step and returns ten one-time recovery codes. Confirmation, disable and recovery regeneration revoke all sessions and advance security version. DisableMFA and RegenerateMFARecovery require current password plus a valid factor. AuthContext must come from host-verified authentication, never request JSON.

Return secrets and recovery codes once through a non-cacheable authenticated response. Never put them in URLs, logs, browser-history props, flashes or authenticated session state.

## Storage and compatibility

TOTP is six-digit SHA-1 with a 30-second period and one-step skew. Accepted steps advance a persisted monotonic watermark. Recovery codes contain 256 random bits; their digest binds the explicit persistent domain, subject and factor ID. Secret encryption uses AES-GCM with a random nonce and the stored key ID. Keep historical keys during rotation.

The shared codec requires an explicit trusted domain. Native local factors use goauth/mfa. The AuthHub adapter uses authhub/mfa and preserves its existing AAD, recovery digest format, factor rows, encryption key IDs and central SSO session writer. No destructive data migration or duplicate canonical factor store is introduced.

All factor writes use subject-first locking and exact factor ID/revision comparisons. CompleteLocalLogin revalidates expiry after final lock acquisition and before session creation. Public secret/token results are withheld on transaction errors, including unknown commit outcomes. The schema verifier checks tables, indexes, column types and nullability; migration integration tests additionally inspect critical unique, foreign-key and CHECK constraints.
