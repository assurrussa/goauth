.DEFAULT_GOAL := check
.PHONY: check tidy-check tidy generate fmt lint vet test test-race bench-all cover-html
GO_MODULE := $(shell go list -m)
GO_FILES := $(shell find . -type f -name '*.go' -not -path './.cache/*' -not -path './.go-cache/*' -not -path './tmp/*' -not -path './vendor/*')
SITE_REPO ?= ../site
GOCACHE ?= $(CURDIR)/.go-cache/gocache
GOMODCACHE ?= $(CURDIR)/.go-cache/gomodcache
GOPATH ?= $(CURDIR)/.go-cache/gopath
export GOCACHE
export GOPATH

check: tidy generate fmt vet lint test test-race cover-html

tidy-check:
	go mod tidy -diff

tidy:
	go mod tidy

generate:
	go generate ./...

fmt:
	go fmt ./...
	gofumpt -l -w $(GO_FILES)
	gci write -s standard -s default -s "prefix($(GO_MODULE))" .

lint:
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
	@go test -coverprofile=./coverage.text -covermode=atomic $(shell go list ./...)
	@go tool cover -html=./coverage.text -o ./cover.html && rm ./coverage.text
