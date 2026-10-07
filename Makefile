# The targets here are the contract. BOOTSTRAP.md 2 names
# them; keep the two in step.

GO      ?= go
PODMAN  ?= podman
BIN     := bin
VERSION := $(shell git describe --tags --always --dirty \
	2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build test lint fmt vet style golden golden-build clean help

all: lint test build

## build: compile the daemon into bin/
build:
	$(GO) build -ldflags '$(LDFLAGS)' -o $(BIN)/ ./cmd/...

## test: run the Go unit tests
test:
	$(GO) test ./...

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
	@if [ ! -f openldap/configure ]; then \
		echo "openldap/ is empty; run:"; \
		echo "  git submodule update --init openldap"; \
		exit 1; \
	fi
	@echo "golden-build: not implemented (plan step 5)."
	@echo "It will build slapd from openldap/ at $$(git -C \
		openldap describe --tags --always) in a rootless"
	@echo "$(PODMAN) container and expose it over TCP."
	@exit 1

## golden: diff Olivine against the C oracle
golden:
	@echo "golden: not implemented (plan step 5)."
	@echo "Corpus is the 113 entries in openldap/tests/scripts."
	@exit 1

clean:
	$(GO) clean ./...
	rm -rf $(BIN)

## help: list these targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
