.DEFAULT_GOAL := full

.PHONY: full prepare check tidy-check tidy generate fmt lint lint-fix vet test test-race bench-all cover-html externalconsumer-local externalconsumer-published release-readiness

GO_MODULE := $(shell GOWORK=off go list -m)
GO_FILES := $(shell find . -type f -name '*.go' -not -path './.cache/*' -not -path './.go-cache/*' -not -path './tmp/*' -not -path './vendor/*')
VERSION ?= v0.1.1
GOCACHE ?= $(CURDIR)/.go-cache/gocache
GOMODCACHE ?= $(CURDIR)/.go-cache/gomodcache
GOPATH ?= $(CURDIR)/.go-cache/gopath
export GOCACHE
export GOMODCACHE
export GOPATH

full: prepare check

prepare: tidy generate fmt lint-fix

check: tidy-check vet lint test test-race cover-html externalconsumer-local

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

lint:
	golangci-lint run -v --timeout=5m ./...

lint-fix:
	golangci-lint run -v --fix --timeout=5m ./...

vet:
	go vet ./...

test:
	go test ./...

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
