.DEFAULT_GOAL := full

.PHONY: full prepare check tidy-check tidy generate fmt fmt-check lint lint-fix vet test test-full test-race bench-all cover-html externalconsumer-local externalconsumer-published release-readiness

GO_MODULE := $(shell GOWORK=off go list -m)
GO_FILES := $(shell find . -type f -name '*.go' -not -path './.cache/*' -not -path './.go-cache/*' -not -path './tmp/*' -not -path './vendor/*')
VERSION ?= v0.1.6
GOCACHE ?= $(CURDIR)/.go-cache/gocache
GOMODCACHE ?= $(CURDIR)/.go-cache/gomodcache
GOPATH ?= $(CURDIR)/.go-cache/gopath
export GOCACHE
export GOMODCACHE
export GOPATH

full: prepare check

prepare: tidy generate fmt lint-fix

check: tidy-check fmt-check vet lint test-full externalconsumer-local

release-readiness: check externalconsumer-published

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
	golangci-lint run -v --timeout=5m ./...

lint-fix:
	golangci-lint run -v --fix --timeout=5m ./...

vet:
	go vet ./...

test:
	go test ./...

test-full:
	go test -race -cover -covermode=atomic -count=1 ./...

test-race:
	go test -race -count=5 ./...

bench-all:
	go test -bench=. -benchmem ./...

cover-html:
	@packages="$$(go list ./...)"; \
	go test -coverprofile=./coverage.text -covermode=atomic $$packages; \
	go tool cover -html=./coverage.text -o ./cover.html; \
	rm ./coverage.text

externalconsumer-local:
	go run ./cmd/externalconsumerprobe --local-path "$(CURDIR)" --go-mod-cache "$(GOMODCACHE)"

externalconsumer-published:
	go run ./cmd/externalconsumerprobe --version "$(VERSION)" --go-mod-cache "$(GOMODCACHE)"
