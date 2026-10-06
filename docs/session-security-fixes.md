# Session security fixes

These changes fix canonical refresh replay retention and the concurrent local
Login/email-confirmation race. They add no public symbols or migrations.

## Canonical refresh retention

`Runtime.Cleanup` retains every selector, HMAC digest and consumed marker in a
canonical refresh family while that family/session can remain active. Token
expiry or consumption alone no longer starts its retention period. The complete
chain is eligible only after the session's fixed expiry, its revocation, or the
family's revocation, plus `ExpiredRecordRetention` (24 hours by default).
The existing strict `< cutoff` boundary is preserved. This uses persisted
lifetimes, including custom TTLs and changes to refresh policy, not a hard-coded
30-day delay. A correctly authenticated replay still revokes the current family
and session and records `refresh.replay`; an incorrect secret does neither.

The fix cannot reconstruct token history already deleted by earlier cleanup.
Previously deleted tokens remain invalid, but their replay cannot be attributed
to a still-active family. Any decision to revoke pre-existing sessions as part
of rollout is a separate operator decision, not a migration or action of this
patch.

Cleanup locks canonical subjects before their dependent rows, matching rotation
and revocation. Busy subjects are skipped until a later run. Whole chains are
removed together, preserving their self-referencing replacement links. This is
not a row-count-bounded operation. Hosts should continue to use an appropriate
maintenance timeout and cadence.

Notification expiry, OIDC cleanup, canonical refresh/session cleanup and the
remaining generic cleanup own successive transactions. Earlier maintenance may
have committed if a later phase fails; an error does not mean global rollback.
The new phase releases canonical security locks before unrelated recovery and
rate/audit cleanup. Cleanup is maintenance, not a participating host write in
`InAuthTransaction`. OIDC's existing retention/batching routine is unchanged.

## Login concurrent with confirmation

Local Login keeps its password-verified subject/version/primary-email snapshot.
After hooks and signing, it locks and revalidates that snapshot before inserting
a session. If the only admission change is that the same user-realm email became
verified, Login discards the prepared pair and prepares a fresh authenticated
pair once, outside the transaction. `ClaimsEnricher` can therefore run twice for
this narrow race; hooks must tolerate repeated preparation. Password verification
and login admission are not repeated. No discarded session or refresh family is
persisted or returned.

Any different subject/version/identifier, inactive account or further incompatible
state change fails closed. Admin/custom realm verification and membership gates
are unchanged. Built-in PostgreSQL and testkit `CreateSession` also reject a scope
inconsistent with the locked email-verification state; they never change signed
scope in SQL. Custom stores must preserve that documented contract.

If Login commits first, normal confirmation promotes its existing session. Its
already issued confirmation JWT is rejected by server-side authentication after
promotion; offline verification still exposes its restricted confirmation scope.
A later refresh reflects the promoted session. If confirmation commits first,
the new Login pair and persisted session are both authenticated. Reusing a verified challenge does not need to
repair a stranded confirmation session.

## Release boundary

The published `v0.5.1` tag is commit
`0862228fd3d3e33d5cc46ed7fc92136df247bdbe`, with schema version 3. The implementation
base, master `318b0370c8fd623a55264b536694dca715733b60`, is unreleased and uses schema
version 8. These fixes do not make all intervening master changes a patch release.
Do not rewrite existing tags or automatically migrate a production database.

Both fixes use contracts and canonical columns already present in `v0.5.1`.
A narrow schema-3 backport is possible, but its maintenance integration must retain
the release branch's own OIDC layout rather than copy the whole master file.
Published `v0.5.1` predates master's separate OIDC retention/locking corrections;
a backport of only these two fixes does not include those corrections.

The selected release is now the full `v0.6.0` master release with the schema 3→8
migration review; see [the upgrade and rollback guide](v0.6-migration.md).
A narrow backport would be a separate release decision. Run the release readiness
and clean public-consumer gates for the exact new tag before claiming a published
fix. Focused regressions or a passing PR do not establish that release.
