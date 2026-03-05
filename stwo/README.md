# S2Circuits - ZK Proofs for Symmetric Encryption

Zero-knowledge proof circuits for AES-128-CTR, AES-256-CTR, and ChaCha20 using [Stwo](https://github.com/starkware-libs/stwo) (Circle STARKs).

## What It Proves

"I know a secret key K such that encrypting plaintext with K produces this ciphertext."

- **Private input:** Key only
- **Public inputs:** Nonce, counter, plaintext, ciphertext

## Prerequisites

### 1. Rust (Nightly)

Install rustup if you don't have it:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

The correct nightly version is specified in `rust-toolchain.toml` and will be installed automatically on first build.

### 2. WASM Target

```bash
rustup target add wasm32-unknown-unknown
```

### 3. wasm-pack (for WASM builds)

```bash
cargo install wasm-pack
```

### 4. wasm-opt (optional, for optimized builds)

wasm-pack will download this automatically, or install via:
```bash
# Ubuntu/Debian
apt install binaryen

# macOS
brew install binaryen
```

## Building

```bash
# Run tests
make test

# Build optimized WASM
make build

# Build debug WASM (faster compile)
make build-dev

# See all targets
make help
```

## Output

After `make build`, the `pkg/` directory contains:
- `s2circuits_bg.wasm` - WASM binary
- `s2circuits.js` - JavaScript bindings
- `s2circuits.d.ts` - TypeScript definitions
- `example.html` - Demo page

## API

### Combined Prove + Verify

```javascript
import init, { prove_aes128_ctr_encrypt } from './s2circuits.js';

await init();

const result = prove_aes128_ctr_encrypt(key, nonce, counter, plaintext, ciphertext);
// Returns: {"success": true, "blocks": N, "algorithm": "aes128-ctr"}
```

### Separate Prove / Verify

```javascript
import init, {
    generate_aes128_ctr_proof,
    verify_aes_ctr_proof
} from './s2circuits.js';

await init();

// Generate proof (returns base64-encoded proof)
const proofResult = generate_aes128_ctr_proof(key, nonce, counter, plaintext, ciphertext);
const { proof } = JSON.parse(proofResult);

// Verify proof (can be done without the key)
const verifyResult = verify_aes_ctr_proof(proof);
// Returns: {"valid": true, "algorithm": "aes128-ctr"}
```

## Supported Algorithms

| Algorithm | Key Size | Block Size | Function |
|-----------|----------|------------|----------|
| AES-128-CTR | 16 bytes | 16 bytes | `prove_aes128_ctr_encrypt` |
| AES-256-CTR | 32 bytes | 16 bytes | `prove_aes256_ctr_encrypt` |
| ChaCha20 | 32 bytes | 64 bytes | `prove_chacha20_encrypt` |


