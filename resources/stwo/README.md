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

// Verify proof (can be done without the key, but with expected public inputs)
const verifyResult = verify_aes_ctr_proof(
  proof,
  nonce,
  counter,
  plaintext,
  ciphertext
);
// Returns: {"valid": true, "algorithm": "aes128-ctr"}
```

## Supported Algorithms

| Algorithm | Key Size | Block Size | Function |
|-----------|----------|------------|----------|
| AES-128-CTR | 16 bytes | 16 bytes | `prove_aes128_ctr_encrypt` |
| AES-256-CTR | 32 bytes | 16 bytes | `prove_aes256_ctr_encrypt` |
| ChaCha20 | 32 bytes | 64 bytes | `prove_chacha20_encrypt` |

## Security Model

### Public Input Binding

The AIR binds nonce, counter, plaintext, and ciphertext to public columns for each supplied block.
The verifier reconstructs these columns from its expected bytes and compares their commitment with the proof.
AIR equality constraints connect the public columns to the encryption trace.

Fiat-Shamir also includes the statement hashes in the transcript.
Transcript inclusion alone does not prove that public bytes match trace cells.
The earlier implementation lacked this connection and accepted unrelated traces under attacker-chosen statements.

### Public Columns

Each trace row represents one encryption block.
The public columns contain an active selector, nonce bytes, counter bytes, plaintext bytes, and ciphertext bytes.
The counter starts at the supplied value and increases by one for each block.
AES uses big-endian counter bytes. ChaCha20 uses little-endian counter bytes.

The active selector equals one for every supplied block and zero for padding rows.
Padding rows still satisfy the encryption constraints, but their data is not part of the public statement.
The verifier derives the selector from the public data length.
A prover cannot omit a supplied block by choosing a different selector or commitment.

For AES, the reconstructed commitment also includes the fixed S-box table.
The verifier rejects a different preprocessed commitment before STARK verification.

### Verification API

The production verification functions require the expected public bytes:

- `verify_stream_with_public_inputs` for ChaCha20.
- `verify_aes_ctr_with_public_inputs` for AES-128-CTR and AES-256-CTR.

These functions compare the expected bytes and hashes with the statement.
They reconstruct the public commitment and then verify the STARK constraints.
The functions without external inputs verify the embedded statement only.
Applications must supply their expected inputs to verify a specific encryption claim.

### Regression Tests

`cargo test security` includes tests for these attacks:

- A prover chooses a false statement before proof generation, with an unrelated valid encryption witness.
- A prover changes nonce, counter, plaintext, or ciphertext independently before proof generation.
- A custom prover commits public columns for its own data while the transcript contains a false statement.
- An attacker changes the statement after proof generation.
- A verifier supplies inputs that differ from the statement.

The tests cover ChaCha20 and both AES key sizes.
Other tests cover valid proofs, padding, multiple SIMD batches, and proof serialization.

### Proof Format

The JavaScript and WASM function signatures remain unchanged.
Proofs include the public plaintext and ciphertext bytes so the verifier can reconstruct their commitment.
The binary proof format changed. Previous proofs require regeneration.
Both the prover and verifier require the rebuilt WASM artifact.
