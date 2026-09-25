.PHONY: build run clean test lint install

APP_NAME=vecscan
MAIN_PATH=./cmd/vecscan

build:
	@echo "Building $(APP_NAME)..."
	@go build -o $(APP_NAME) $(MAIN_PATH)/main.go
	@echo "Build complete!"

run: build
	@./$(APP_NAME) -h

clean:
	@rm -f $(APP_NAME)
	@echo "Clean complete!"

install:
	@go install $(MAIN_PATH)/main.go
	@echo "Install complete!"

test:
	@go test -v ./...

lint:
	@golangci-lint run

fmt:
	@go fmt ./...

deps:
	@go mod download
	@go mod tidy

help:
	@echo "Available targets:"
	@echo "  make build   - Build the application"
	@echo "  make run     - Run the application"
	@echo "  make clean   - Clean build artifacts"
	@echo "  make install - Install the application"
	@echo "  make test    - Run tests"
	@echo "  make lint    - Run linters"
	@echo "  make fmt     - Format code"
	@echo "  make deps    - Download dependencies"