.PHONY: all build build-release build-dev clean test check install zip help setup

RESOURCES_DIR := ../resources/stwo
JS_STWO_DIR := ../js/src/stwo

# Default target
all: build

# Install prerequisites
setup:
	@echo "Installing prerequisites..."
	rustup target add wasm32-unknown-unknown
	cargo install wasm-pack
	@echo "Setup complete."

# Build WASM for production (optimized) and install
build: build-release install

build-release:
	@command -v wasm-pack >/dev/null 2>&1 || { echo "Error: wasm-pack not found. Run 'make setup' first."; exit 1; }
	wasm-pack build --target nodejs --release --out-dir pkg-nodejs
	@echo "WASM build complete in pkg-nodejs/"

# Build WASM for development (faster compile, debug info)
build-dev:
	wasm-pack build --target nodejs --dev --out-dir pkg-nodejs
	@echo "Dev build complete in pkg-nodejs/"

# Install built artifacts
install:
	@echo "Installing artifacts..."
	mkdir -p $(RESOURCES_DIR)
	mkdir -p $(JS_STWO_DIR)
	# WASM binary goes to resources (not part of JS package)
	cp pkg-nodejs/s2circuits_bg.wasm $(RESOURCES_DIR)/
	# JS glue code and types go to js/src/stwo (part of JS package)
	cp pkg-nodejs/s2circuits.js $(JS_STWO_DIR)/s2circuits.cjs
	cp pkg-nodejs/s2circuits.d.ts $(JS_STWO_DIR)/
	# Patch the WASM path to load from resources
	sed -i "s|const wasmPath = .*s2circuits_bg.wasm.*|const path = require('path');\nconst wasmPath = path.join(__dirname, '..', '..', '..', 'resources', 'stwo', 's2circuits_bg.wasm');|" $(JS_STWO_DIR)/s2circuits.cjs
	@echo ""
	@echo "Installed:"
	@echo "  $(RESOURCES_DIR)/s2circuits_bg.wasm"
	@echo "  $(JS_STWO_DIR)/s2circuits.cjs"
	@echo "  $(JS_STWO_DIR)/s2circuits.d.ts"

# Run Rust tests
test:
	cargo test --lib

# Run Rust tests with output
test-verbose:
	cargo test --lib -- --nocapture

# Check code compiles without building
check:
	cargo check
	cargo check --target wasm32-unknown-unknown

# Clean build artifacts
clean:
	cargo clean
	rm -rf pkg-nodejs pkg-bundler pkg-node pkg

# Create distribution zip
zip: build
	cd $(RESOURCES_DIR) && zip -r ../stwo.zip s2circuits_bg.wasm
	@echo "Created resources/stwo.zip"

# Format code
fmt:
	cargo fmt

# Lint code
lint:
	cargo clippy --target wasm32-unknown-unknown

help:
	@echo "s2circuits WASM build targets:"
	@echo ""
	@echo "  make setup        - Install prerequisites (wasm-pack, wasm target)"
	@echo "  make build        - Build optimized WASM and install (default)"
	@echo "  make build-release- Build optimized WASM only (no install)"
	@echo "  make build-dev    - Build debug WASM (faster compile)"
	@echo "  make install      - Copy built artifacts to destinations"
	@echo "  make test         - Run Rust tests"
	@echo "  make test-verbose - Run tests with output"
	@echo "  make check        - Check compilation"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make zip          - Create distribution zip"
	@echo "  make fmt          - Format code"
	@echo "  make lint         - Run clippy"
	@echo ""
	@echo "Output:"
	@echo "  WASM:     $(RESOURCES_DIR)/s2circuits_bg.wasm"
	@echo "  JS/Types: $(JS_STWO_DIR)/s2circuits.{cjs,d.ts}"
