.PHONY: build test test-fast clean lint fmt vet tools install-tools

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet

# Build targets
BINARY_DIR=bin
DICT_CONVERTER=$(BINARY_DIR)/dict-converter
DICT_VALIDATOR=$(BINARY_DIR)/dict-validator
EXAMPLE_SERVER=$(BINARY_DIR)/example-server
EXAMPLE_CLIENT=$(BINARY_DIR)/example-client

# Test parameters
TEST_RACE=-race
TEST_TIMEOUT=10m
TEST_COVERAGE=-coverprofile=coverage.out

all: build

# Build all binaries
build: tools
	mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(DICT_CONVERTER) ./cmd/dict-converter
	$(GOBUILD) -o $(DICT_VALIDATOR) ./cmd/dict-validator
	$(GOBUILD) -o $(EXAMPLE_SERVER) ./cmd/example-server
	$(GOBUILD) -o $(EXAMPLE_CLIENT) ./cmd/example-client

# Run tests with race detector and coverage
test:
	$(GOTEST) $(TEST_RACE) -timeout $(TEST_TIMEOUT) $(TEST_COVERAGE) ./...

# Run tests without race detector (faster for development)
test-fast:
	$(GOTEST) -timeout $(TEST_TIMEOUT) ./...

# Format code
fmt:
	$(GOFMT) -s -w .

# Vet code
vet:
	$(GOVET) ./...

# Lint code
lint: tools
	golangci-lint run


# Check if tools are available
tools:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found. && exit 1)

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BINARY_DIR)
	rm -f coverage.out

# Tidy dependencies
tidy:
	$(GOMOD) tidy

# Download dependencies
deps:
	$(GOMOD) download

# Run all checks (format, vet, lint, test)
check: fmt vet lint test

# Development workflow
dev: fmt vet test-fast

# Release build (with all checks)
release: check build
