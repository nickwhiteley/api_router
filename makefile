.DEFAULT_GOAL := build

.PHONY: fmt vet lint build clean dev unit-test e2e-test test build-all quick-build docs-check docs-serve

# Ensure bin directory exists
bin:
	mkdir -p bin

fmt:
	go fmt ./...

vet: fmt
	go vet ./...

lint: vet
	@echo "Running golangci-lint on each package (excluding scripts)..."
	@for dir in $$(find . -name "*.go" -not -path "./scripts/*" -exec dirname {} \; | sort -u); do \
		echo "  Checking $$dir..."; \
		golangci-lint run "$$dir"; \
	done

build: vet bin
	go build -o bin/api-router ./cmd/server

build-with-lint: lint bin
	go build -o bin/api-router ./cmd/server

clean:
	rm -rf bin/*
	rm -rf tmp/*

# Build all binaries
build-all: bin
	go build -o bin/api-router ./cmd/server
	go build -o bin/migrate ./cmd/migrate
	go build -o bin/admin-token ./cmd/admin-token

# Quick build without checks (for development)
quick-build: bin
	go build -o bin/api-router ./cmd/server

# Documentation targets
docs-check:
	@echo "Checking documentation structure..."
	@test -f docs/README.md || (echo "docs/README.md missing" && exit 1)
	@test -d docs/deployment || (echo "docs/deployment directory missing" && exit 1)
	@echo "Documentation structure OK"

docs-serve:
	@echo "Documentation is available in the docs/ directory"
	@echo "Open docs/README.md to get started"

dev: vet
	go run ./cmd/server/main.go

unit-test:
	go test ./... -v

e2e-test: unit-test
	./scripts/run_e2e_tests.sh

test: e2e-test