.PHONY: build test lint lint-install fmt vet image run clean

BIN := prometheus_pihole_exporter
PKG := ./cmd/$(BIN)

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

# Single source of truth for the golangci-lint version. Read from
# .golangci-lint-version so the devcontainer postCreate, the CI
# workflow, and `make lint` can't drift apart. To upgrade, edit that
# file in one place.
LINTER_VERSION := $(shell cat .golangci-lint-version)
LINTER_BIN     := ./bin/golangci-lint-$(LINTER_VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ./bin/$(BIN) $(PKG)

test:
	go test -race -cover ./...

# `make lint` always runs the project-pinned golangci-lint binary,
# never whatever happens to be on PATH. The binary lives at
# ./bin/golangci-lint-<version> so multiple checkouts on the same
# host don't clobber each other.
lint: lint-install
	$(LINTER_BIN) run ./...

lint-install:
	@if [ ! -x "$(LINTER_BIN)" ]; then \
		echo ">> installing golangci-lint $(LINTER_VERSION) into $(LINTER_BIN)"; \
		mkdir -p ./bin; \
		tmp=$$(mktemp -d); \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
			| sh -s -- -b "$$tmp" "$(LINTER_VERSION)"; \
		mv "$$tmp/golangci-lint" "$(LINTER_BIN)"; \
		rm -rf "$$tmp"; \
	fi

fmt:
	gofmt -s -w .

vet:
	go vet ./...

image:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(DATE) \
		-t $(BIN):$(VERSION) .

run: build
	./bin/$(BIN) -config ./examples/config.yaml

clean:
	rm -rf ./bin
