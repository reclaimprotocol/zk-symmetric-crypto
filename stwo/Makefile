.PHONY: all build build-release build-dev clean test check pkg zip help setup

# Default target
all: build

# Install prerequisites
setup:
	@echo "Installing prerequisites..."
	rustup target add wasm32-unknown-unknown
	cargo install wasm-pack
	@echo "Setup complete."

# Build WASM for production (optimized)
build: build-release

build-release:
	@command -v wasm-pack >/dev/null 2>&1 || { echo "Error: wasm-pack not found. Run 'make setup' first."; exit 1; }
	wasm-pack build --target web --release --out-dir pkg
	mkdir -p ../resources/stwo
	cp pkg/s2circuits_bg.wasm ../resources/stwo/
	cp pkg/s2circuits.js ../js/src/stwo/
	cp pkg/s2circuits.d.ts ../js/src/stwo/
	@echo "Build complete: resources/stwo/ and js/src/stwo/"

# Build WASM for development (faster compile, debug info)
build-dev:
	wasm-pack build --target web --dev --out-dir pkg
	cp pkg/s2circuits_bg.wasm ../resources/stwo/
	cp pkg/s2circuits.js ../js/src/stwo/
	@echo "Dev build complete: resources/stwo/ and js/src/stwo/"

# Build for Node.js
build-node:
	wasm-pack build --target nodejs --release
	@echo "Node.js build complete: pkg/"

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
	rm -rf pkg/*.wasm pkg/*.js pkg/*.ts pkg/package.json pkg/.gitignore

# Create distribution zip
zip: build-release
	cd pkg && zip -r s2.zip s2circuits_bg.wasm s2circuits.js s2circuits.d.ts s2circuits_bg.wasm.d.ts package.json
	@echo "Created pkg/s2.zip"

# Serve example.html locally (requires python3)
serve:
	cd pkg && python3 -m http.server 8080

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
	@echo "  make build        - Build optimized WASM (default)"
	@echo "  make build-dev    - Build debug WASM (faster compile)"
	@echo "  make build-node   - Build for Node.js"
	@echo "  make test         - Run Rust tests"
	@echo "  make test-verbose - Run tests with output"
	@echo "  make check        - Check compilation"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make zip          - Create distribution zip"
	@echo "  make serve        - Serve pkg/ on localhost:8080"
	@echo "  make fmt          - Format code"
	@echo "  make lint         - Run clippy"
	@echo ""
	@echo "Prerequisites: Rust nightly (auto-installed via rust-toolchain.toml)"
