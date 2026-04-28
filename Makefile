SHELL := /usr/bin/env bash

.PHONY: install-tools build test test-race test-cover lint fmt mocks check

install-tools:
	go install github.com/vektra/mockery/v3@v3.7.0
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4

build:
	go build ./...

test:
	go test ./...

test-race:
	go test -race ./...

test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	golangci-lint run ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

mocks:
	mockery

check: fmt build test lint
