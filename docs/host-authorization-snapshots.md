# Host authorization snapshots and transaction outcomes

These additive PostgreSQL Runtime APIs support a host-owned optional cache. They
neither enable caching nor change membership, session, MFA or RBAC policy.

`Runtime.AuthorizationSnapshot(ctx, project)` reads RBAC and host-owned projections
in a single read-only REPEATABLE READ transaction. `project` receives an opaque
`SQLExecutor`, not transaction ownership. Use that executor, consume/close all rows,
and never retain it. The returned RBAC snapshot and any captured host data may be
published **only after a nil return**. Discard both on projection or commit failure.
Ambient managed transactions are rejected, including foreign database handles.
This avoids mixed membership/permission generations without copying canonical SQL.

`Runtime.ObserveAuthTransaction(ctx, observer)` registers a bounded host callback
before host writes in a managed auth transaction. Reuse one observer pointer per
cache; registration coalesces across nested scopes. Nested scopes join the outer
transaction, not a savepoint: an inner error caught by the outer caller does not
itself imply rollback. The callback receives only the final outer outcome:

- Committed: invalidate/fence the local cache and request a fresh snapshot.
- RolledBack: release any host reservation; no mutation became committed.
- Unknown: fence the cache and reconcile storage; do not assume rollback/retry.

Observers run synchronously outside registration locks after completion. Use a
bounded context independent of HTTP cancellation, never the transaction context
or executor. Do not panic; if an observer does panic, remaining registered hooks
still run before the first panic is propagated. Callback delivery is process-local,
not durable, and callback failure cannot undo a committed transaction. Completed,
foreign and absent transaction scopes are rejected. Register before mutations and
propagate registration errors. Standalone operations must be wrapped explicitly in
`InAuthTransaction`; this API cannot observe arbitrary external SQL transactions.

Hosts still own atomic publication, generation fences, lifecycle, max-age expiry,
periodic refresh for external writers/other pods, and complete write coverage.
Never replace session introspection or transactional write invariants with these
snapshots. No schema changes, production opt-in or public release are implied.

`Runtime.AuthTransactionActive(ctx)` inspects the canonical managed scope without
SQL or observer registration. A host's transactional guard must bypass read caches
when true, including direct Runtime transactions without host-specific markers.
False without error means no scope; foreign, completed and canceled scopes return
an error which must not be interpreted as permission to use a cached grant.
This query does not extend transaction lifetime; existing callback/concurrency
rules still apply. It does not claim that an arbitrary external SQL transaction
is managed by GoAuth.

For an admin-only cache, use `ScopedAuthorizationSnapshot(ctx, selectSubjects)`.
The selector reads host membership using the supplied executor and returns canonical
subject IDs before canonical RBAC reads, all within the same read-only Repeatable
Read transaction. Subject assignments are filtered by `subject_id=ANY($1::uuid[])`
in PostgreSQL using the existing subject-first primary key, not loaded and filtered
in Go. Empty/nil selected IDs return no assignments; a nil selector is an error.
The complete role/permission catalog remains available, including unassigned roles,
for role management/preview. Catalog entries are not grants: authorization must use
only the selected subjects' assignments. Memory scales with the catalog plus the
selected assignments, not all customer assignments. The unscoped APIs remain
unchanged. Captured selector results are provisional until the entire call succeeds.
