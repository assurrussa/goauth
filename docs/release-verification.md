# Release Verification

## Baseline

Current verified baseline: `v0.1.1`.

Do not rewrite existing tags. If preparation or verification changes generated
files, formatting, `go.mod`, or `go.sum`, commit those changes and release a new
semver tag.

## Local Verification

Run the full local gate from the repository root:

```sh
make
```

This runs preparation and verification:

- `go mod tidy`
- `go generate ./...`
- formatting through `go fmt`, `gofumpt`, and `gci`
- `golangci-lint run --fix`
- `go mod tidy -diff`
- `go vet ./...`
- `golangci-lint run`
- `go test ./...`
- `go test -race -count=5 ./...`
- coverage HTML generation
- local external-consumer probe

For non-mutating verification after preparation:

```sh
make check
```

## Clean Consumer Probes

Local checkout probe:

```sh
make externalconsumer-local
```

Published module probe:

```sh
make externalconsumer-published VERSION=v0.1.1
```

Full release-readiness gate:

```sh
make release-readiness VERSION=v0.1.1
```

`cmd/externalconsumerprobe` creates a temporary Go module, imports the packages
listed by `reference/externalconsumer`, and runs:

```sh
go test -mod=mod ./... -count=1
```

With `--version`, it first resolves `github.com/assurrussa/goauth@<version>`
via `go list -m -json`.

## Sandbox Cache Note

Raw `go` commands can fail in a restricted sandbox if they try to use the global
Go build cache. Prefer Makefile targets, or use:

```sh
GOCACHE=$PWD/.go-cache/gocache \
GOMODCACHE=$PWD/.go-cache/gomodcache \
GOPATH=$PWD/.go-cache/gopath \
go test ./...
```

## Host Consumer Follow-Up

After publishing a new `goauth` tag, known host repositories should remove local
`replace` directives and verify against the published module version.

For `/Users/amir/dev/projects/my/site`, `RELEASING.md` currently documents:

```sh
cd /Users/amir/dev/projects/my/site
task platform:published-check GOAUTH_VERSION=v0.1.1 GOADMIN_VERSION=v0.2.1
```

Treat local `replace` success as sibling-development evidence only. It is not
proof that a clean external consumer can resolve the published module.
