# Runtime hot-path microbenchmarks

These fixtures measure a small, fixed, sequential workload against the existing
in-memory `testkit.Store` and `fixtureTransaction`. They do not measure PostgreSQL,
HTTP middleware, network latency, host membership, contention, or sustained load.
No production default, API, cache, schema, dependency, or CI trigger is changed.

## Cases and exact configuration

`BenchmarkRuntimeHotPaths` in `testkit/hotpath_benchmark_test.go` contains four cases:

- `testkit/user/Login/argon2id_m19456_t2_p1`: successful `Runtime.Login`, including
  real Argon2id password verification, identifier normalization, the real
  testkit login rate limiter, lookup/admission, random session/refresh generation,
  HS256 signing, and the fixture auth transaction. The configured built-in hasher
  uses Argon2id v19, memory 19,456 KiB, two iterations, one lane, 16-byte salt, and
  32-byte derived key. The Runtime hash/verification budget is four slots;
  this benchmark uses one caller. Legacy compatibility is disabled. It is not a
  fast-password-double result or a concurrency-capacity test.
- `testkit/user/VerifyJWT/offline_HS256`: `Runtime.VerifyJWT` signature and claims
  validation of one already-issued token. It performs no storage authentication.
- `testkit/user/AuthenticateSession/storage_HS256`: `Runtime.AuthenticateSession`
  on the same kind of token, including current testkit session, subject-status,
  security-version, subject, realm, and scope checks. The user realm does not
  invoke the host membership gate. No admin/custom-realm claim is implied.
- `testkit/user/Refresh/success_first_rotation`: `Runtime.Refresh` from one
  valid, unconsumed token, including parsing/HMAC, peek, realm admission,
  generation/signing, and transactional rotation. Each measured operation starts
  from the same pre-rotation state and must return a different refresh token in
  the original session. It finishes with exactly one consumed and one live token.
  This does not measure replay or a long refresh chain.

The shared fixture has one active, email-verified subject at security version 1,
one normalized email identifier, and one local credential. The initial login
fixture has no sessions, refresh families, tokens, audit events, or rate events.
Login finishes with one session, one family, one token, and one rate event in one
bucket. Session/refresh setup performs one real login outside timing. Session
reads retain that fixed dataset. Refresh starts with that dataset and ends with
two token records. All other tables remain empty. Successful operations must
leave the audit and notification sinks empty.

`testkit.NewRuntime` supplies its existing fixture key rings (distinct 32-byte
JWT, token-HMAC, and outbox-AEAD keys), issuer `https://auth.example.test`, and
audience `test`. Access TTL is the existing five-minute default; session and
refresh TTLs are the existing 30-day defaults. The default login quota remains
10 attempts in 15 minutes. The clock is frozen at 2026-10-10 00:00:00 UTC so long
benchmark calibration cannot turn valid tokens into expired-token measurements.
Random generation uses the existing cryptographic randomness, not a scripted
reader. No claims enricher is configured. All credentials and keys are test-only.

## Timing and bounded state

Runtime construction, dummy and fixture password hashing, account creation, and
session seed login occur outside measured time and allocations. Each write case
restores only the state these success paths mutate while the timer is stopped:
session maps, independently copied refresh-family/token structs, audit history,
and copied rate-event history. Restoring the initial quota history retains the
real admission cost without eventually timing rejection. Restoring unconsumed
refresh state prevents replay and removes the preceding operation's new token.
The immutable baseline is never consumed.

The measured operation still pays for the existing fixture transaction snapshot
of its constant-size dataset. There is no replacement transaction implementation
and no production reset helper. The reset helper is test-only, serial, and never
copies a mutex. Do not use it from `RunParallel`.

Login/refresh validation and reset work are outside measured time. Session loops
include a function-value call, error checking, and small result assertions. Both
session cases use the same wrapper. Every iteration must succeed with the
expected authenticated user identity; write cases also check fixed cardinality.
All four cases call `ReportAllocs`.

Per-operation stop/start introduces substantial untimed harness overhead for
fast write paths. Excluded fixture allocations can still affect GC/cache state;
these are controlled microbenchmarks, not isolation from allocator effects.
Prefer a fixed operation count for an initial smoke check and record the exact
timing mode for comparisons. Do not compare to HTTP or database-backed latency.

## Commands and results capture

Run only in an already authorized, writable checkout with the patch applied and
the repository's required Go toolchain/dependencies available. Honor its existing
shared-cache configuration. Do not use the old dirty retained checkout as the
pinned benchmark source, invent fresh cache locations, or create another runtime
just to work around an execution restriction.

Compile and exercise every branch for 12 operations, exceeding the default
10-attempt login quota so a missing reset cannot silently pass:

```sh
go test ./testkit -run='^$' -bench='^BenchmarkRuntimeHotPaths$' -benchtime=12x -count=1 -cpu=1 -benchmem
```

The smoke run checks fixture behavior; its very short timing is not a baseline.
For retained comparative samples, choose an operation count appropriate to the
host and budget, keep it identical across revisions, and save unedited output.
For example, these explicit starting settings are not a workload SLA:

```sh
set -o pipefail
go test ./testkit -run='^$' -bench='^BenchmarkRuntimeHotPaths$' -benchtime=100x -count=5 -cpu=1 -benchmem 2>&1 | tee goauth-runtime-hotpaths.raw.txt
```

The existing independent RBAC fixture remains separate and unchanged:

```sh
go test ./rbac -run='^$' -bench='^BenchmarkCheck$' -benchtime=100x -count=5 -cpu=1 -benchmem
```

The examples pin benchmark `GOMAXPROCS` to one with `-cpu=1`; they do not prescribe
production concurrency. The repository's existing `make bench-all` runs `go test -bench=. -benchmem ./...`
and also runs ordinary tests. The manual retained-sample mode below runs only the
two named benchmark suites. Neither smoke nor retained-sample mode replaces the
normal required repository checks.

Alongside raw benchmark rows and exit status, retain:

- exact source commit, complete applied-patch SHA-256 values, and final tree diff;
- `go version`, `go env GOOS GOARCH`, configured `GOGC`/`GOMEMLIMIT` (or their
  toolchain defaults), CPU model/count, benchmark `-cpu`/effective `GOMAXPROCS`,
  OS/kernel, available memory, and host load;
- the exact command, count/repetitions, parallelism setting, and run timestamps;
- backend `testkit.Store`/`fixtureTransaction`, the fixed dataset and clock above,
  hasher parameters, key/algorithm profile (never real key material), and realm;
- full `ns/op`, `B/op`, and `allocs/op` rows with the operation count, without
  substituting test-package elapsed time or reporting synthetic percentile data.

Compare only matching case names and configurations. These results cannot supply
a PostgreSQL or production baseline. A real-store run still needs its own
disposable canonical schema, database/version/pool configuration, dataset sizes,
realm/membership workload, and separately reviewed measurement fixtures.

## Validation evidence

The manually dispatched CI workflow compiles the fixtures and runs a 12-operation
smoke check. Inspect the exact source commit's run logs to confirm that all four
Runtime cases and all five RBAC cases executed successfully. A configured step,
source review, or zero exit status without the expected case rows does not prove
that every benchmark ran.

Smoke runs validate fixture behavior, including bounded login quota state beyond
ten operations. Their short timing rows are not a retained performance baseline.
Use the repeated-run procedure and matching configuration above before drawing
performance conclusions. Keep actual pass, failure, and skipped-stage evidence
with the relevant commit or pull request rather than inferring it from this guide.

## Manual retained-sample mode

In the existing CI workflow, select the intended source ref and
`validation_scope=baseline`. The default remains `full`; `fixtures` keeps its
existing behavior. Baseline mode runs a separate benchmark-only job with no
PostgreSQL/Redis services, race instrumentation, or full test/lint/vulnerability
gates. It does not add any automatic workflow trigger.

Both commands above use exactly 100 measured operations, five repetitions, and
one benchmark CPU. This mode sets `GOMAXPROCS=1`, `GOGC=100`,
`GOMEMLIMIT=off`, and `GOFLAGS=-mod=readonly`. It uses the Go version required
by `go.mod`. A clean committed checkout is required before and after capture.
The fixtures and production implementation are unchanged.

The RBAC cases use the existing in-process store/cache test doubles:
uncached allow/deny, cache-hit allow/deny, and cache miss. They do not measure a
real cache, database, invalidation, or cross-process behavior. Runtime cases use
the dataset, hashing, algorithms, frozen clock, and timing exclusions above.

A successful capture requires every Runtime case five times (20 rows) and every
RBAC case five times (25 rows), each with operation count 100 and finite,
nonnegative `ns/op`, `B/op`, and `allocs/op`. Missing/extra cases,
missing/excess repetitions, malformed rows, errors, or missing/duplicate package
success markers fail the job. A failed command retains partial evidence and
cannot be called a completed baseline.

The `goauth-hotpath-baseline-<source-sha>-<attempt>` artifact is retained for 90
days and contains:

- Unedited `runtime.raw.txt` and `rbac.raw.txt` with all repetitions.
- Exact commands, package exit statuses, and start/end UTC timestamps.
- Source commit/tree, clean source diff, fixture/workflow/module/document hashes,
  the complete configuration guide, and run URL/attempt.
- Go version/build settings, GC/memory/parallelism settings, runner image,
  OS/kernel, CPU model/count, available memory, and before/after host load.
- Capture log and final capture exit status, including assertion failures.

Download the artifact before expiry if it is needed for longer-term comparison.
Retain all repeated rows rather than only a summary, and use matching fixture,
toolchain, timing mode, configuration, and hardware for comparisons. Hosted
runners can vary and 100 operations is especially noisy for very fast RBAC
checks. These are small retained microbenchmark samples, not statistically
stable latency estimates, percentiles, a production SLA, or a PostgreSQL
baseline. Increase the controlled sample budget in a separately reviewed run
before relying on small differences.
