.PHONY: help build run dev test test-race lint fmt vet tidy clean docker-up docker-down

BINARY ?= cannect
PKG    ?= ./...
PORT   ?= 8080

help:
	@echo "Cannect backend — available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?##"} {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Compile the binary into ./bin
	@CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(BINARY) ./cmd/cannect

run: build ## Build and run the server
	@PORT=$(PORT) ./bin/$(BINARY)

dev: ## Run with `go run` (no binary)
	@PORT=$(PORT) go run ./cmd/cannect

test: ## Run tests
	@go test $(PKG)

test-race: ## Run tests with the race detector
	@go test -race -count=1 $(PKG)

lint: ## Run golangci-lint
	@golangci-lint run

fmt: ## gofmt
	@go fmt $(PKG)

vet: ## go vet
	@go vet $(PKG)

tidy: ## go mod tidy
	@go mod tidy

clean: ## Remove build artifacts
	@rm -rf bin/

docker-up: ## Spin up mongo+redis+app via compose
	@docker compose up -d --build

docker-down: ## Tear down compose stack
	@docker compose down
