APP_NAME=lmap
CMD_DIR=./cmd/lanmap
VERSION=v1.0.0
BUILD_DIR=./dist

.PHONY: all build clean test cross-compile

all: build

build:
	@echo "Building $(APP_NAME)..."
	go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(APP_NAME) $(CMD_DIR)

test:
	@echo "Running tests..."
	go test -v ./...

cross-compile: clean
	@mkdir -p $(BUILD_DIR)
	@echo "Cross-compiling for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 $(CMD_DIR)
	@echo "Cross-compiling for Linux (arm64)..."
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(CMD_DIR)
	@echo "Cross-compiling for macOS (arm64 - Apple Silicon)..."
	GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 $(CMD_DIR)
	@echo "Cross-compiling for macOS (amd64 - Intel)..."
	GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 $(CMD_DIR)
	@echo "Cross-compiling for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe $(CMD_DIR)
	@echo "All binaries successfully built in $(BUILD_DIR)/"

clean:
	@rm -f $(APP_NAME)
	@rm -rf $(BUILD_DIR)
