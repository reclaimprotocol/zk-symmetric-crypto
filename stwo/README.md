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

## Security Model

### Public Input Binding

This implementation uses **Fiat-Shamir hash binding** to cryptographically bind public inputs (nonce, counter, plaintext, ciphertext) to STARK proofs. This section documents the security model for auditors.

#### How It Works

1. **AIR Constraints**: The constraint system enforces correct encryption:
   ```
   ciphertext = AES(key, nonce || counter) XOR plaintext
   ```
   or for ChaCha20:
   ```
   ciphertext = ChaCha20(key, nonce, counter) XOR plaintext
   ```

2. **Fiat-Shamir Binding**: Public inputs are hashed (Blake2s) and mixed into the channel before challenges are derived:
   ```rust
   // In prove/verify:
   stmt0.mix_into(channel);  // Mixes hash(nonce, counter, plaintext, ciphertext)
   commitment_scheme.commit(..., channel);
   let challenges = channel.draw(...);  // Challenges depend on public input hashes
   ```

3. **Verification**: The verifier:
   - Computes hash of their expected public inputs
   - Compares against proof's embedded hash (fast-fail check)
   - Runs STARK verification with same channel mixing
   - If hashes differ, challenges differ, FRI verification fails

#### Security Properties

| Property | Mechanism | Assumption |
|----------|-----------|------------|
| Soundness | AIR constraints + FRI | Standard STARK assumptions |
| Public input binding | Fiat-Shamir hash mixing | Blake2s collision resistance |
| Key privacy | Key only in private witness | ZK property of STARKs |

#### Comparison with Other Approaches

**Groth16/gnark approach:**
- Public inputs are directly part of the pairing verification equation
- Verifier evaluates: `e(A, B) = e(α, β) · e(∑ aᵢGᵢ, γ) · e(C, δ)`
- Mathematical binding via group operations

**This STARK approach:**
- Public inputs are hashed and mixed into Fiat-Shamir transcript
- Verifier recomputes hash, compares, then verifies STARK
- Cryptographic binding via hash collision resistance

Both approaches are secure. The STARK approach is more flexible (can bind arbitrary data) but requires the hash comparison step.

#### Threat Model

**Attacker capabilities:**
- Can generate valid proofs for data they know the key for
- Can intercept and modify serialized proofs
- Cannot find Blake2s collisions (256-bit security)

**Attack: Tampered public inputs in serialized proof**
```
1. Attacker generates valid proof for (nonce_A, counter_A, plaintext_A, ciphertext_A)
2. Attacker modifies proof.stmt0.public_inputs to claim (nonce_B, counter_B, plaintext_B, ciphertext_B)
3. Verifier receives tampered proof
```

**Defense:**
- Verifier computes `hash(nonce_B, counter_B, plaintext_B, ciphertext_B)`
- Hash differs from proof's embedded hash
- `verify_*_with_public_inputs` returns error immediately (fast-fail)
- Even without fast-fail, STARK verification would fail because:
  - Channel state differs (different hash mixed in)
  - Challenges differ
  - FRI polynomial commitments don't match

**Attack: Hash collision**
```
1. Attacker finds (data_A, data_B) where Blake2s(data_A) = Blake2s(data_B)
2. Generates proof for data_A, claims it's for data_B
```

**Defense:**
- Blake2s has 256-bit output, collision resistance ~2^128
- This is considered computationally infeasible

#### Security Tests

The codebase includes explicit security tests (`cargo test security`):

1. `test_aes_tampered_public_inputs_in_proof` - Verifies that modifying public inputs in a serialized proof causes verification failure
2. `test_chacha_tampered_public_inputs_in_proof` - Same for ChaCha20
3. `test_aes_verify_with_wrong_public_inputs` - Verifies that correct proof fails when verifier supplies different public inputs
4. `test_chacha_verify_with_wrong_public_inputs` - Same for ChaCha20

#### Recommendations for Auditors

1. **Verify Fiat-Shamir transcript completeness**: Check that `mix_into` is called before any challenge derivation
2. **Verify constraint correctness**: Check that AIR constraints enforce the encryption relationship
3. **Verify hash comparison**: Check that `verify_*_with_public_inputs` compares hashes before STARK verification
4. **Check serialization**: Ensure proof deserialization doesn't allow injection attacks


