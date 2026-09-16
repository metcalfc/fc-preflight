BIN := fc-preflight
VERSION := $(shell sed -n 's/^const version = "\(.*\)"/\1/p' main.go)

.PHONY: all
all: help

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  %-14s %s\n", $$1, $$2}'

.PHONY: build
build: ## Build for the host platform
	go build -trimpath -o $(BIN) .

.PHONY: release
release: ## Build static linux/amd64 and linux/arm64 binaries into dist/
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/$(BIN)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/$(BIN)-linux-arm64 .
	@cd dist && shasum -a 256 $(BIN)-linux-* > SHA256SUMS 2>/dev/null || sha256sum $(BIN)-linux-* > SHA256SUMS
	@ls -l dist/

.PHONY: test
test: ## Run the test suite
	go test ./...

.PHONY: check
check: ## Everything CI would run: fmt, vet on both arches, test, build both arches
	gofmt -l . | tee /dev/stderr | (! read)
	GOOS=linux GOARCH=amd64 go vet ./...
	GOOS=linux GOARCH=arm64 go vet ./...
	go test ./...
	GOOS=linux GOARCH=amd64 go build -o /dev/null .
	GOOS=linux GOARCH=arm64 go build -o /dev/null .
	@echo "all checks passed"

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN) dist
