# Owned auth transactions

`postgres.Runtime.InOwnedAuthTransaction(ctx, fn)` requires ownership of one
outermost managed auth transaction on the Runtime's exact `*sql.DB` handle. It is
intended for host entry points that prepare a shown-once credential, token or
final authorization response and must confirm commit before publishing it.

- A context with a managed transaction on the same handle returns
  `postgres.ErrAuthTransactionAlreadyActive` before `fn`, writes or a second BEGIN.
  Another Runtime sharing that exact handle is also rejected. An owned call inside
  another owned callback is rejected in the same way.
- A context from a different handle is rejected even when its DSN is identical.
  Handle ownership is tracked by GoAuth's managed scope, not context identity or
  inspection of executors. Never discard or strip a callback's context to bypass
  ownership checks. Unmanaged transactions are outside this scope contract.
- With no managed scope, it starts one read-committed transaction. Existing
  `InAuthTransaction`, canonical operations, audit, enqueue, RBAC and host SQL using
  `SQLExecutor(ctx)` can join it. Existing joining APIs retain their behavior.
- Callback errors roll back. Nil is returned only after a successful commit and
  existing commit callbacks. Cancellation and commit errors use the existing auth
  transaction classification. `goauth.ErrOperationOutcomeUnknown` means commit
  could have happened; a server-rejected commit is not classified as unknown.
  Cache invalidation and unknown/rollback hooks keep their existing behavior.

## Callback and executor are different contracts

Both transaction methods take `func(context.Context) error`, not
`func(SQLExecutor) error`. Their current exported signatures are:

```go
func (r *Runtime) InAuthTransaction(ctx context.Context, fn func(context.Context) error) error
func (r *Runtime) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error
func (r *Runtime) SQLExecutor(ctx context.Context) (SQLExecutor, error)
```

These are API declarations from `postgres/host_transaction.go`, not a runnable
program. Inside the callback, obtain the borrowed executor with
`executor, err := runtime.SQLExecutor(txctx)` and propagate the error. Use the
same `txctx` for participating auth operations and host SQL. The callback receives
the managed **context**; the separately obtained executor cannot commit or roll
back. Do not use `Database()` or a separately started SQL transaction for writes
that must commit atomically with auth state. See the complete
[host-session example](../examples/hostsession/README.md) for runnable wiring.

## Withhold provisional results

Prepare any response inside the callback, but publish it only after the owned
method returns nil. The callback must not write HTTP responses, send tokens or
otherwise expose prepared data. Every error returns an empty response to the
caller, including unknown outcomes. GoAuth cannot retract a callback's external
side effects. An unknown outcome requires reconciliation or an explicitly designed
idempotent flow; it must not be interpreted as a confirmed rollback or blindly
retried. Confirmed commit does not guarantee subsequent network response delivery.

```go
func prepareResponse(ctx context.Context, runtime *postgres.Runtime) (string, error) {
    var prepared string
    err := runtime.InOwnedAuthTransaction(ctx, func(txctx context.Context) error {
        // Perform participating checks and writes using txctx.
        // Assign the provisional response without publishing it here.
        prepared = "prepared response"
        return nil
    })
    if err != nil {
        return "", err
    }
    return prepared, nil
}
```

The host owns response content and policy. Do not retain the managed context or
executor beyond the callback. Join all concurrent operations before returning;
serialize mixed SQL result-set/query/write use on the transaction connection and
consume and close result sets before another operation. The executor grants SQL
execution only, never transaction ownership. No schema upgrade, new supported
package, required interface change or public Subject change is needed.
