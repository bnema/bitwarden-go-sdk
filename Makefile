SHELL := /usr/bin/env bash

GO_PACKAGES := $(shell go list ./... 2>/dev/null)
GO_FILES := $(shell find . -name '*.go' -not -path './.git/*')

.PHONY: install-tools build test test-race test-cover lint fmt mocks check

install-tools:
	go install github.com/vektra/mockery/v3@v3.8.1
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4

build:
	@if [[ -n "$(GO_PACKAGES)" ]]; then go build ./...; else echo "no Go packages to build"; fi

test:
	@if [[ -n "$(GO_PACKAGES)" ]]; then go test ./...; else echo "no Go packages to test"; fi

test-race:
	@if [[ -n "$(GO_PACKAGES)" ]]; then go test -race ./...; else echo "no Go packages to test"; fi

test-cover:
	@if [[ -n "$(GO_PACKAGES)" ]]; then go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out; else echo "no Go packages to cover"; fi

lint:
	@if [[ -n "$(GO_PACKAGES)" ]]; then golangci-lint run ./...; else echo "no Go packages to lint"; fi

fmt:
	@if [[ -n "$(GO_FILES)" ]]; then gofmt -w $(GO_FILES); else echo "no Go files to format"; fi

mocks:
	@if [[ -d internal/ports ]]; then mockery; else echo "no ports to mock"; fi

check: fmt build test lint
