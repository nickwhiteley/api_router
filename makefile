.DEFAULT_GOAL := build

.PHONY:fmt vet build
fmt:
	go fmt ./...
vet: fmt
	go vet ./...
lint : vet
	@echo "Running golangci-lint on each package (excluding scripts)..."
	@for dir in $$(find . -name "*.go" -not -path "./scripts/*" -exec dirname {} \; | sort -u); do \
		echo "  Checking $$dir..."; \
		golangci-lint run "$$dir"; \
	done
build: lint
	go build -o bin/ ./*.go

.DEFAULT_GOAL := build


dev: lint
	go run ./cmd/server/main.go

dev1: vet
	go run ./cmd/server/main.go

unit-test:
	go test ./... -v
e2e-test: unit-test
	./scripts/run_e2e_tests.sh
test: e2e-test