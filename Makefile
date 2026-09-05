APP_NAME=lanmap
CMD_DIR=./cmd/lanmap
VERSION=v0.0.16
BUILD_DIR=./dist

.PHONY: all build clean test test-federation cross-compile package

all: build

build:
	@echo "Building $(APP_NAME) ($(VERSION))..."
	go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(APP_NAME) $(CMD_DIR)

test:
	@echo "Running tests..."
	go test -v ./internal/db ./internal/federation ./internal/i18n ./internal/monitor ./internal/scanner ./internal/updater ./internal/web

test-federation:
	@echo "Running federation & remote agent E2E tests..."
	go test -v ./internal/db -run TestFederation
	go test -v ./internal/web -run TestFederation
	go test -v ./internal/federation/...

cross-compile: clean
	@mkdir -p $(BUILD_DIR)/tmp
	@echo "Cross-compiling and packaging ZIP archives (<appname>-<os>-<arch>.zip)..."
	
	@# macOS arm64 (Apple Silicon)
	@echo "  -> Packaging $(APP_NAME)-mac-arm64.zip"
	@GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/tmp/$(APP_NAME) $(CMD_DIR)
	@(cd $(BUILD_DIR)/tmp && zip -q ../$(APP_NAME)-mac-arm64.zip $(APP_NAME))
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME)
	
	@# Linux x64
	@echo "  -> Packaging $(APP_NAME)-linux-x64.zip"
	@GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/tmp/$(APP_NAME) $(CMD_DIR)
	@(cd $(BUILD_DIR)/tmp && zip -q ../$(APP_NAME)-linux-x64.zip $(APP_NAME))
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME)
	
	@# Linux arm64
	@echo "  -> Packaging $(APP_NAME)-linux-arm64.zip"
	@GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/tmp/$(APP_NAME) $(CMD_DIR)
	@(cd $(BUILD_DIR)/tmp && zip -q ../$(APP_NAME)-linux-arm64.zip $(APP_NAME))
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME)
	
	@# Windows x64
	@echo "  -> Packaging $(APP_NAME)-win-x64.zip"
	@GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/tmp/$(APP_NAME).exe $(CMD_DIR)
	@(cd $(BUILD_DIR)/tmp && zip -q ../$(APP_NAME)-win-x64.zip $(APP_NAME).exe)
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME).exe
	
	@# Windows arm64
	@echo "  -> Packaging $(APP_NAME)-win-arm64.zip"
	@GOOS=windows GOARCH=arm64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/tmp/$(APP_NAME).exe $(CMD_DIR)
	@(cd $(BUILD_DIR)/tmp && zip -q ../$(APP_NAME)-win-arm64.zip $(APP_NAME).exe)
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME).exe
	
	@rm -rf $(BUILD_DIR)/tmp
	@echo "\n✅ Successfully generated all ZIP archives in $(BUILD_DIR)/:"
	@ls -lh $(BUILD_DIR)/*.zip

package: cross-compile

clean:
	@rm -f $(APP_NAME)
	@rm -rf $(BUILD_DIR)
