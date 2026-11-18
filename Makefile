# Development tasks for the safetech module.
#
# Run "make" or "make help" to list the available targets.

GO ?= go
GOLANGCI_LINT ?= golangci-lint

.DEFAULT_GOAL := help

.PHONY: help tidy fmt vet lint test cover test-integration security check all

help: ## Show this help.
	@printf 'Usage: make [target]\n\n'
	@printf 'Targets:\n'
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

tidy: ## Update go.mod and go.sum, removing unused dependencies.
	$(GO) mod tidy

fmt: ## Format Go files (gofumpt when installed, gofmt otherwise).
	@if command -v gofumpt >/dev/null 2>&1; then \
		echo "gofumpt -l -w ."; \
		gofumpt -l -w .; \
	else \
		echo "gofmt -l -w ."; \
		gofmt -l -w .; \
	fi

vet: ## Run go vet.
	$(GO) vet ./...

lint: ## Run golangci-lint.
	$(GOLANGCI_LINT) run ./...

test: ## Run the unit tests with the race detector.
	$(GO) test -race ./...

cover: ## Run the unit tests and print total statement coverage.
	$(GO) test -race -covermode=atomic -coverprofile=coverage.out ./...
	@$(GO) tool cover -func=coverage.out | tail -n 1
	@echo "profile written to coverage.out; open it with: $(GO) tool cover -html=coverage.out"

test-integration: ## Run the live-CA integration test (needs STCA_* environment variables).
	@if [ -z "$$STCA_BASE_URL" ] || [ -z "$$STCA_USERNAME" ] || [ -z "$$STCA_PASSWORD" ]; then \
		echo "STCA_BASE_URL, STCA_USERNAME and STCA_PASSWORD must be set" >&2; \
		exit 1; \
	fi
	$(GO) test -tags=integration -race -v -run TestIntegration ./...

security: ## Run govulncheck and gosec.
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "govulncheck not installed; install it with:" >&2; \
		echo "  go install golang.org/x/vuln/cmd/govulncheck@latest" >&2; \
		exit 1; \
	}
	@command -v gosec >/dev/null 2>&1 || { \
		echo "gosec not installed; install it with:" >&2; \
		echo "  go install github.com/securego/gosec/v2/cmd/gosec@latest" >&2; \
		exit 1; \
	}
	govulncheck ./...
	gosec -quiet ./...

check: tidy fmt vet lint test ## Run tidy, fmt, vet, lint and test.

all: check cover security ## Run every quality gate.
