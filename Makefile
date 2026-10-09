# The targets here are the contract. BOOTSTRAP.md 2 names
# them; keep the two in step.

GO      ?= go
PODMAN  ?= podman
BIN     := bin
VERSION := $(shell git describe --tags --always --dirty \
	2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

# The registry the image is pushed to. Override to publish
# elsewhere.
REGISTRY ?= ghcr.io/fatmanuk
IMAGE    ?= $(REGISTRY)/olivine-ldap

.PHONY: all build test race store postgres-down lint fmt \
	fmt-check vet style width-check golden golden-data \
	golden-acl golden-build clean help

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

## store: run the store tests against a throwaway Postgres
##        (plain `make test` skips them)
store:
	@dsn=$$(./scripts/postgres-up.sh) && \
		OLIVINE_TEST_DSN="$$dsn" \
		$(GO) test -count=1 ./internal/store/

## golden-acl: compare access-control behaviour against the C
##            (needs Postgres and the oracle image)
golden-acl:
	@dsn=$$(./scripts/postgres-up.sh) && \
		OLIVINE_TEST_DSN="$$dsn" \
		$(GO) test -tags golden -count=1 -v \
			-run TestGoldenACL ./internal/golden/

## golden-limits: compare search limits against the C
golden-limits:
	@dsn=$$(./scripts/postgres-up.sh) && \
		OLIVINE_TEST_DSN="$$dsn" \
		$(GO) test -tags golden -count=1 -v \
			-run TestGoldenLimits ./internal/golden/

## golden-paged: compare paged results against the C
golden-paged:
	@dsn=$$(./scripts/postgres-up.sh) && \
		OLIVINE_TEST_DSN="$$dsn" \
		$(GO) test -tags golden -count=1 -v \
			-run TestGoldenPaged ./internal/golden/

## golden-sasl: compare a SASL EXTERNAL bind against the C
golden-sasl:
	@dsn=$$(./scripts/postgres-up.sh) && \
		OLIVINE_TEST_DSN="$$dsn" \
		$(GO) test -tags golden -count=1 -v \
			-run TestGoldenSASLExternal ./internal/golden/

## postgres-down: remove the throwaway Postgres
postgres-down:
	@./scripts/postgres-down.sh

## lint: gofmt, go vet and the project style invariants
lint: fmt-check vet width-check

## fmt-check: fail if anything is not gofmt-clean
fmt-check:
	@out=$$(gofmt -l $$(git ls-files --cached --others \
		--exclude-standard '*.go' | grep -v '^openldap/') \
		2>/dev/null); \
	if [ -n "$$out" ]; then \
		echo "gofmt needed:"; echo "$$out"; exit 1; \
	else echo "gofmt: ok"; fi

vet:
	$(GO) vet ./...

## width-check: 70 columns, functions at most 40 lines
width-check:
	@./scripts/check-style.sh

# Kept as the names used before the CI settled on fmt-check and
# width-check.
fmt: fmt-check
style: width-check

## pod-build: build the Olivine server image (rootless Podman)
pod-build:
	$(PODMAN) build -t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest \
		-f deploy/Containerfile .

## pod-push: push the image to the registry
pod-push:
	$(PODMAN) push $(IMAGE):$(VERSION)
	$(PODMAN) push $(IMAGE):latest

## pod-run: run the image against a throwaway Postgres
pod-run:
	@./scripts/pod-run.sh

## golden-build: build the C oracle container from openldap/
golden-build:
	@./scripts/golden-build.sh

## golden: diff Olivine against the C oracle (protocol only)
golden:
	$(GO) test -tags golden -count=1 ./internal/golden/

## golden-data: the same, with a seeded tree on both sides
##             (needs Postgres as well as the oracle image)
golden-data:
	@dsn=$$(./scripts/postgres-up.sh) && \
		OLIVINE_TEST_DSN="$$dsn" \
		$(GO) test -tags golden -count=1 -v \
			-run 'TestGoldenData|Vacuous' \
			./internal/golden/

clean:
	$(GO) clean ./...
	rm -rf $(BIN)

## help: list these targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
