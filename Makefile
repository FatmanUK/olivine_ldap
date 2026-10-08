# The targets here are the contract. BOOTSTRAP.md 2 names
# them; keep the two in step.

GO      ?= go
PODMAN  ?= podman
BIN     := bin
VERSION := $(shell git describe --tags --always --dirty \
	2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build test race lint fmt vet style golden \
	golden-build clean help

all: lint test build

## build: compile the daemon into bin/
build:
	$(GO) build -ldflags '$(LDFLAGS)' -o $(BIN)/ ./cmd/...

## test: run the Go unit tests
test:
	$(GO) test ./...

## race: run the tests under the race detector
race:
	$(GO) test -race ./...

## lint: gofmt, go vet and the project style invariants
lint: fmt vet style

fmt:
	@out=$$(gofmt -l $$(git ls-files --cached --others \
		--exclude-standard '*.go' | grep -v '^openldap/') \
		2>/dev/null); \
	if [ -n "$$out" ]; then \
		echo "gofmt needed:"; echo "$$out"; exit 1; \
	else echo "gofmt: ok"; fi

vet:
	$(GO) vet ./...

## style: 70 columns, functions at most 40 lines
style:
	@./scripts/check-style.sh

## golden-build: build the C oracle container from openldap/
golden-build:
	@./scripts/golden-build.sh

## golden: diff Olivine against the C oracle
golden:
	$(GO) test -tags golden -count=1 ./internal/golden/

clean:
	$(GO) clean ./...
	rm -rf $(BIN)

## help: list these targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
