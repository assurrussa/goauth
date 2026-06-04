# Implementation Notes

## 2026-06-04 Project Initialization Docs

- Kept repository docs in English to match the existing README, RELEASING, and
  AUTH_INVARIANTS files.
- Treated `goauth` as a reusable published module, not a host application.
- Used local repo files as the source of truth and checked shared
  agent-context pages only after local grounding.
- Preserved the public-surface rule that `reference/externalconsumer` is the
  machine-readable support manifest.
- Added focused `docs/` files instead of expanding README with agent-only
  operational details.
- Recorded the repo-local Go cache requirement because raw `go list ./...`
  failed against the global Go build cache under the current sandbox, while the
  same command succeeds with `.go-cache/` paths.
- Did not touch existing modified files outside this documentation task.
