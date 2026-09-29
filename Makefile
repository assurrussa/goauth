.DEFAULT_GOAL := full

.PHONY: full prepare check tidy-check tidy generate fmt fmt-check lint lint-fix vet test test-full test-race bench-all cover-html coverage-unit-check coverage-integration-check coverage-aggregate integration integration-up integration-down integration-local vulnerability-check externalconsumer-local externalconsumer-postgres-local externalconsumer-published release-candidate-readiness release-readiness release-tooling-test release-source-check public-module-check browser-acceptance backup-restore-check release-evidence-check public-preview-readiness

GO_MODULE := $(shell awk '$$1 == "module" { print $$2; exit }' go.mod)
GO_FILES := $(shell find . -type f -name '*.go' -not -path './.cache/*' -not -path './.go-cache/*' -not -path './tmp/*' -not -path './vendor/*')
# Published checks must not silently verify a stale default version.
VERSION ?=
# Keep SHA-bound evidence outside the clean checkout; no stale default manifest.
EVIDENCE ?=
GOCACHE ?= $(CURDIR)/.go-cache/gocache
GOMODCACHE ?= $(CURDIR)/.go-cache/gomodcache
GOPATH ?= $(CURDIR)/.go-cache/gopath
GOLANGCI_LINT_CACHE ?= $(CURDIR)/.go-cache/golangci-lint
GOAUTH_TEST_POSTGRES_DSN ?= postgres://goauth:goauth@127.0.0.1:55432/goauth_integration?sslmode=disable
GOAUTH_TEST_REDIS_ADDRESS ?= 127.0.0.1:56379
COVERAGE_UNIT ?= coverage.unit.out
COVERAGE_INTEGRATION ?= coverage.integration.out
COVERAGE_AGGREGATE ?= coverage.out
export VERSION
export EVIDENCE
export GOCACHE
export GOMODCACHE
export GOPATH
export GOLANGCI_LINT_CACHE
export GOAUTH_TEST_POSTGRES_DSN
export GOAUTH_TEST_REDIS_ADDRESS

full: prepare check

prepare: tidy generate fmt lint-fix

check: release-tooling-test tidy-check fmt-check vet lint test-full coverage-unit-check externalconsumer-local

release-candidate-readiness: check integration vulnerability-check coverage-aggregate backup-restore-check browser-acceptance

# Serialize the tag guard before either gate, including under make -j.
release-readiness: release-source-check
	$(MAKE) release-candidate-readiness
	$(MAKE) externalconsumer-published

# The executable gates do not prove all 38 security/host/operational observations.
# Full public-preview acceptance additionally requires their reviewed manifest.
public-preview-readiness: release-readiness
	$(MAKE) release-evidence-check

release-evidence-check:
	@test -n "$$EVIDENCE" || { printf 'EVIDENCE is required; select the reviewed release-SHA manifest.\n' >&2; exit 1; }
	go run ./cmd/releaseevidence --file "$$EVIDENCE" --version "$$VERSION"

public-module-check: release-source-check
	$(MAKE) externalconsumer-published

release-source-check:
	sh ./scripts/check-release-source.sh "$$VERSION"

release-tooling-test:
	sh ./scripts/check-release-source-test.sh

tidy-check:
	go mod tidy -diff

tidy:
	go mod tidy

generate:
	go generate ./...

fmt:
	go fmt ./...
	gofumpt -l -w $(GO_FILES)
	gci write -s standard -s default -s "prefix($(GO_MODULE))" $(GO_FILES)

fmt-check:
	@unformatted="$$(gofumpt -l $(GO_FILES))"; \
		test -z "$$unformatted" || { printf 'gofumpt changes are required:\n%s\nRun: make prepare\n' "$$unformatted" >&2; exit 1; }
	@import_diff="$$(gci diff -s standard -s default -s "prefix($(GO_MODULE))" $(GO_FILES))"; \
		test -z "$$import_diff" || { printf 'gci changes are required:\n%s\nRun: make prepare\n' "$$import_diff" >&2; exit 1; }

lint:
	golangci-lint run --timeout=5m ./...

lint-fix:
	golangci-lint run --fix --timeout=5m ./...

vet:
	go vet ./...

test:
	go test ./...

test-full:
	go test -race -covermode=atomic -coverprofile=$(COVERAGE_UNIT) -count=1 ./...

coverage-unit-check:
	sh ./scripts/check-coverage.sh $(COVERAGE_UNIT) .=80 oidc/provider=80 rbac=80 redis=80

test-race:
	go test -race -count=5 ./...

bench-all:
	go test -bench=. -benchmem ./...

cover-html: test-full
	go tool cover -html=$(COVERAGE_UNIT) -o ./cover.html

integration:
	go test -race -tags=integration -covermode=atomic -coverprofile=$(COVERAGE_INTEGRATION) -count=1 ./postgres ./redis
	$(MAKE) coverage-integration-check
	$(MAKE) externalconsumer-postgres-local

coverage-integration-check:
	sh ./scripts/check-coverage.sh $(COVERAGE_INTEGRATION) postgres=80 redis=80

coverage-aggregate:
	sh ./scripts/merge-coverprofiles.sh $(COVERAGE_AGGREGATE) $(COVERAGE_UNIT) $(COVERAGE_INTEGRATION)
	go tool cover -func=$(COVERAGE_AGGREGATE)

integration-up:
	docker compose -f compose.integration.yml -p goauth-v02-integration up -d --wait

integration-down:
	docker compose -f compose.integration.yml -p goauth-v02-integration down -v

# Explicit invocations must fail when their tools/engine are missing.
browser-acceptance:
	GOAUTH_BROWSER_ACCEPTANCE=1 go test -race -tags=integration -run '^TestPostgresBrowserAcceptance$$' -count=1 ./examples/nethttp

backup-restore-check:
	GOAUTH_TEST_BACKUP_RESTORE=1 go test -race -tags=integration -run '^TestPostgresBackupRestore$$' -count=1 ./postgres

integration-local: integration-up
	@status=0; \
		$(MAKE) integration || status=$$?; \
		docker compose -f compose.integration.yml -p goauth-v02-integration down -v || status=$$?; \
		exit $$status

vulnerability-check:
	go tool govulncheck ./...

externalconsumer-local:
	go run ./cmd/externalconsumerprobe --local-path "$(CURDIR)" --go-mod-cache "$(GOMODCACHE)"

externalconsumer-postgres-local:
	go run ./cmd/externalconsumerprobe --local-path "$(CURDIR)" --go-mod-cache "$(GOMODCACHE)" --postgres-integration

externalconsumer-published:
	@test -n "$$VERSION" || { printf 'VERSION is required; select an exact published tag.\n' >&2; exit 1; }
	go run ./cmd/externalconsumerprobe --version "$$VERSION" --timeout 10m
