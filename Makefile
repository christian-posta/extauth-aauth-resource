.PHONY: help build build-sign-request generate-key run clean generate deps

# Default target
help:
	@echo "Available targets:"
	@echo "  deps             - Install dependencies and generate protobuf code"
	@echo "  build            - Build the aauth-service binary"
	@echo "  build-sign-request - Build the sign-request utility tool"
	@echo "  generate-key     - Generate Ed25519 keypair for resource signing"
	@echo "  run              - Run the aauth-service service"
	@echo "  clean            - Clean generated files and binaries"
	@echo "  generate         - Generate protobuf code only"

# Install dependencies and generate protobuf code
deps: generate
	go mod tidy

# Generate protobuf code using protoc
generate:
	@echo "Generating protobuf code..."
	mkdir -p gen
	protoc --go_out=gen --go_opt=paths=source_relative \
		--go-grpc_out=gen --go-grpc_opt=paths=source_relative \
		proto/ext_authz.proto

# Build the main service binary
build: deps
	go build -o aauth-service ./cmd/server

# Build the sign-request utility tool
build-sign-request: deps
	go build -o sign-request ./cmd/sign-request

# Generate Ed25519 keypair for resource signing
generate-key:
	go run ./cmd/generate-key

# Run the service
run: build
	./aauth-service

# Clean up
clean:
	rm -f aauth-service sign-request
	rm -rf gen/

# Check if protoc is installed
check-protoc:
	@which protoc > /dev/null || (echo "Error: protoc is not installed. Please install Protocol Buffers compiler." && exit 1)
