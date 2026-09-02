APP_NAME=lanmap
CMD_DIR=./cmd/lanmap
VERSION=v0.0.2
BUILD_DIR=./dist
PKG_DIR=./dist/packages

.PHONY: all build clean test cross-compile package

all: build

build:
	@echo "Building $(APP_NAME) ($(VERSION))..."
	go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(APP_NAME) $(CMD_DIR)

test:
	@echo "Running tests..."
	go test -v ./...

cross-compile: clean
	@mkdir -p $(BUILD_DIR)
	@echo "Cross-compiling binaries with <appname>-<os>-<arch> naming..."
	GOOS=darwin  GOARCH=arm64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-mac-arm64 $(CMD_DIR)
	GOOS=darwin  GOARCH=amd64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-mac-x64 $(CMD_DIR)
	GOOS=linux   GOARCH=amd64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-linux-x64 $(CMD_DIR)
	GOOS=linux   GOARCH=arm64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(CMD_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-win-x64.exe $(CMD_DIR)
	GOOS=windows GOARCH=arm64 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(APP_NAME)-win-arm64.exe $(CMD_DIR)
	@echo "Stand-alone binaries created in $(BUILD_DIR)/"

package: cross-compile
	@mkdir -p $(PKG_DIR)
	@echo "Packaging ZIP archives (inner binary: $(APP_NAME))..."
	@rm -rf $(BUILD_DIR)/tmp && mkdir -p $(BUILD_DIR)/tmp
	
	@# macOS arm64
	@cp $(BUILD_DIR)/$(APP_NAME)-mac-arm64 $(BUILD_DIR)/tmp/$(APP_NAME)
	@(cd $(BUILD_DIR)/tmp && zip -q ../packages/$(APP_NAME)-mac-arm64.zip $(APP_NAME))
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME)
	
	@# macOS x64
	@cp $(BUILD_DIR)/$(APP_NAME)-mac-x64 $(BUILD_DIR)/tmp/$(APP_NAME)
	@(cd $(BUILD_DIR)/tmp && zip -q ../packages/$(APP_NAME)-mac-x64.zip $(APP_NAME))
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME)
	
	@# Linux x64
	@cp $(BUILD_DIR)/$(APP_NAME)-linux-x64 $(BUILD_DIR)/tmp/$(APP_NAME)
	@(cd $(BUILD_DIR)/tmp && zip -q ../packages/$(APP_NAME)-linux-x64.zip $(APP_NAME))
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME)
	
	@# Linux arm64
	@cp $(BUILD_DIR)/$(APP_NAME)-linux-arm64 $(BUILD_DIR)/tmp/$(APP_NAME)
	@(cd $(BUILD_DIR)/tmp && zip -q ../packages/$(APP_NAME)-linux-arm64.zip $(APP_NAME))
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME)
	
	@# Windows x64
	@cp $(BUILD_DIR)/$(APP_NAME)-win-x64.exe $(BUILD_DIR)/tmp/$(APP_NAME).exe
	@(cd $(BUILD_DIR)/tmp && zip -q ../packages/$(APP_NAME)-win-x64.zip $(APP_NAME).exe)
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME).exe
	
	@# Windows arm64
	@cp $(BUILD_DIR)/$(APP_NAME)-win-arm64.exe $(BUILD_DIR)/tmp/$(APP_NAME).exe
	@(cd $(BUILD_DIR)/tmp && zip -q ../packages/$(APP_NAME)-win-arm64.zip $(APP_NAME).exe)
	@rm -f $(BUILD_DIR)/tmp/$(APP_NAME).exe
	
	@rm -rf $(BUILD_DIR)/tmp
	@echo "All ZIP packages generated in $(PKG_DIR)/"
	@ls -la $(PKG_DIR)/

clean:
	@rm -f $(APP_NAME)
	@rm -rf $(BUILD_DIR)
