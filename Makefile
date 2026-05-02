PROJECT_NAME := SmileVPN

CLIENT_DIR := ./cmd/client
SERVER_DIR := ./cmd/server
BIN_DIR := ./bin

CLIENT_BIN := $(BIN_DIR)/client
SERVER_BIN := $(BIN_DIR)/server

GO := go
GOFLAGS := -v
LDFLAGS := -ldflags "-s -w"

GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
NC := \033[0m

.PHONY: all
all: clean deps build

.PHONY: build
build: $(CLIENT_BIN) $(SERVER_BIN)

$(CLIENT_BIN): $(shell find $(CLIENT_DIR) -name '*.go')
	@echo "$(GREEN)Building client...$(NC)"
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(CLIENT_BIN) ./$(CLIENT_DIR)

$(SERVER_BIN): $(shell find $(SERVER_DIR) -name '*.go')
	@echo "$(GREEN)Building server...$(NC)"
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(SERVER_BIN) ./$(SERVER_DIR)

.PHONY: run-client
run-client: $(CLIENT_BIN)
	@echo "$(GREEN)Starting client...$(NC)"
	./$(CLIENT_BIN)

.PHONY: run-server
run-server: $(SERVER_BIN)
	@echo "$(GREEN)Starting server...$(NC)"
	./$(SERVER_BIN)

.PHONY: run-both
run-both: build
	@echo "$(GREEN)Starting server in background...$(NC)"
	@./$(SERVER_BIN) & echo $$! > /tmp/server.pid
	@sleep 1
	@echo "$(GREEN)Starting client...$(NC)"
	@./$(CLIENT_BIN)
	@echo "$(YELLOW)Stopping server...$(NC)"
	@kill $$(cat /tmp/server.pid) 2>/dev/null || true
	@rm -f /tmp/server.pid

.PHONY: deps
deps:
	@echo "$(GREEN)Installing dependencies...$(NC)"
	$(GO) mod download
	$(GO) mod tidy

.PHONY: test
test:
	@echo "$(GREEN)Running tests...$(NC)"
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

.PHONY: clean
clean:
	@echo "$(RED)Cleaning...$(NC)"
	@rm -rf $(BIN_DIR)
	@rm -f coverage.out coverage.html
	@rm -f /tmp/server.pid

.PHONY: fmt
fmt:
	@echo "$(GREEN)Formatting code...$(NC)"
	$(GO) fmt ./...

.PHONY: lint
lint:
	@echo "$(GREEN)Running linter...$(NC)"
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "$(RED)golangci-lint not installed. Installing...$(NC)"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.55.2; \
	}
	golangci-lint run

.PHONY: cross-build
cross-build:
	@echo "$(GREEN)Cross-compiling for Linux, Windows, macOS...$(NC)"
	@mkdir -p $(BIN_DIR)

	@echo "$(YELLOW)Building for Linux (amd64)...$(NC)"
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/server-linux-amd64 ./$(SERVER_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/client-linux-amd64 ./$(CLIENT_DIR)

	@echo "$(YELLOW)Building for Windows (amd64)...$(NC)"
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/server-windows-amd64.exe ./$(SERVER_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/client-windows-amd64.exe ./$(CLIENT_DIR)

	@echo "$(YELLOW)Building for macOS (amd64)...$(NC)"
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/server-darwin-amd64 ./$(SERVER_DIR)
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/client-darwin-amd64 ./$(CLIENT_DIR)

	@echo "$(GREEN)Cross-compilation complete!$(NC)"

.PHONY: proto
proto:
	@echo "$(GREEN)Generating protobuf...$(NC)"
	protoc --go_out=. --go-grpc_out=. proto/*.proto

.PHONY: dev
dev:
	@echo "$(GREEN)Starting development mode...$(NC)"
	@command -v air >/dev/null 2>&1 || { \
		echo "$(RED)air not installed. Installing...$(NC)"; \
		go install github.com/cosmtrek/air@latest; \
	}
	air

.PHONY: help
help:
	@echo "$(GREEN)Available commands:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'

.PHONY: version
version:
	@echo "$(GREEN)Go version:$(NC) $(shell go version)"
	@echo "$(GREEN)GOOS:$(NC) $(GOOS)"
	@echo "$(GREEN)GOARCH:$(NC) $(GOARCH)"

.DEFAULT_GOAL := help