# Release Verification

## Baseline

Current verified baseline: `v0.1.6`. The next maintenance candidate is
`v0.1.7`.

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
- non-mutating `gofumpt` and `gci` checks
- one `go test -race -cover -count=1 ./...` pass
- local external-consumer probe

Repeated race stress and HTML coverage are explicit diagnostics through
`make test-race` and `make cover-html`; do not stack them onto an unchanged
successful `make check` run.

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
make externalconsumer-published VERSION=v0.1.7
```

Full release-readiness gate:

```sh
make release-readiness VERSION=v0.1.7
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

For a sibling `site` checkout, `RELEASING.md` currently documents:

```sh
cd ../site
task platform:published-check GOAUTH_VERSION=v0.1.7 GOADMIN_VERSION=v0.4.0-alpha.14
```

Treat local `replace` success as sibling-development evidence only. It is not
proof that a clean external consumer can resolve the published module.
