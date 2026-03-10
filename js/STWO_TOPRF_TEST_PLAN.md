# Stwo TOPRF TypeScript Test Plan

## Overview

This document outlines the plan for adding TypeScript tests for stwo TOPRF, including:
1. Stwo TOPRF operator implementation
2. Cross-compatibility testing between gnark and stwo
3. ZK proof generation and verification tests

## Key Technical Difference

**Hash Functions**:
- **Gnark TOPRF**: Uses MiMC hash over BN254 scalar field
- **Stwo TOPRF**: Uses Poseidon2 hash over M31 field

This means the **OPRF outputs will be different** for the same inputs. However:
- Both use Baby Jubjub curve (same curve parameters)
- Both use DLEQ proofs (same cryptographic structure)
- Both support threshold signatures with Lagrange interpolation
- JSON serialization format is designed to be compatible

## Phase 1: Stwo TOPRF Operator Implementation

### 1.1 Create `js/src/stwo/toprf.ts`

Implement `OPRFOperator` interface using stwo WASM functions:

```typescript
// Methods to implement:
export function makeStwoOPRFOperator(opts: MakeZKOperatorOpts<{}>): OPRFOperator {
  return {
    generateWitness(input: ZKProofInputOPRF): Promise<Uint8Array>
    groth16Prove(witness: Uint8Array): Promise<ZKProofOutput>
    groth16Verify(publicSignals, proof): Promise<boolean>

    // TOPRF-specific methods - call stwo WASM functions:
    generateThresholdKeys(total, threshold): Promise<KeygenResult>
    generateOPRFRequestData(data, domainSeparator): Promise<OPRFRequestData>
    evaluateOPRF(serverPrivateKey, request): Promise<OPRFResponse>
    finaliseOPRF(serverPublicKey, request, responses): Promise<Uint8Array>
  }
}
```

### 1.2 Update `js/src/stwo/s2circuits.d.ts`

Add TypeScript declarations for new WASM functions:

```typescript
// Add to existing declarations:
export function toprf_generate_keys(nodes: number, threshold: number, seed: bigint): string;
export function toprf_create_request(secret_bytes: Uint8Array, domain_separator: string): string;
export function toprf_evaluate(share_json: string, masked_request_hex: string): string;
export function toprf_finalize(params_json: string): string;
export function get_toprf_info(): string;
```

### 1.3 Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `js/src/stwo/toprf.ts` | Create | Stwo TOPRF operator implementation |
| `js/src/stwo/s2circuits.d.ts` | Modify | Add TOPRF function declarations |
| `js/src/stwo/operator.ts` | Modify | Export toprf operator |

## Phase 2: Basic TOPRF Tests

### 2.1 Create `js/src/tests/stwo-toprf.test.ts`

Basic stwo TOPRF functionality tests:

```typescript
describe('stwo TOPRF basic tests', () => {
  // Test key generation
  it('should generate threshold keys')

  // Test OPRF request creation
  it('should create OPRF request')

  // Test OPRF evaluation
  it('should evaluate OPRF')

  // Test finalization
  it('should finalize TOPRF and produce output')

  // Test different secrets produce different outputs
  it('should produce different outputs for different secrets')

  // Test determinism (same inputs = same output)
  it('should be deterministic')

  // Test edge cases
  it('should handle max secret size (62 bytes)')
  it('should handle empty domain separator')
  it('should handle threshold=nodes')
})
```

### 2.2 Update `js/src/tests/oprf.test.ts`

Add stwo to the OPRF test matrix:

```typescript
const OPRF_ZK_ENGINES_MAP: { [E in ZKEngine]?: Config } = {
  'gnark': {
    make: algorithm => makeGnarkOPRFOperator({ fetcher, algorithm }),
    algorithms: ['chacha20', 'aes-128-ctr', 'aes-256-ctr'],
  },
  'stwo': {
    make: algorithm => makeStwoOPRFOperator({ fetcher, algorithm }),
    algorithms: ['chacha20', 'aes-128-ctr', 'aes-256-ctr'],
  }
}
```

## Phase 3: Cross-Compatibility Tests

### 3.1 Create `js/src/tests/toprf-compat.test.ts`

Test compatibility between gnark and stwo:

```typescript
describe('gnark-stwo TOPRF compatibility tests', () => {

  // === Serialization Compatibility ===

  describe('serialization format compatibility', () => {
    it('should serialize points in same format (64 bytes hex)')
    it('should serialize scalars in same format (variable BE hex)')
    it('should use same JSON structure for requests')
    it('should use same JSON structure for responses')
  })

  // === Curve Operation Compatibility ===

  describe('Baby Jubjub curve compatibility', () => {
    it('both use same curve parameters (a=-1, d=168696)')
    it('both use same base point')
    it('both use same scalar order')
    it('gnark point serialization matches stwo deserialization')
    it('stwo point serialization matches gnark deserialization')
  })

  // === Key Generation Compatibility ===

  describe('key generation compatibility', () => {
    it('gnark keys can be deserialized by stwo')
    it('stwo keys can be deserialized by gnark')
    it('both produce valid public keys on curve')
  })

  // === DLEQ Proof Compatibility ===

  describe('DLEQ proof structure compatibility', () => {
    // Note: proofs won't be interchangeable (different hash),
    // but structure should be same
    it('both produce (c, r) tuples')
    it('c and r are valid curve scalars')
    it('proof format is JSON-compatible')
  })

  // === Cross-Evaluation Tests ===

  describe('cross-system evaluation', () => {
    // Test: gnark generates keys, stwo evaluates
    it('stwo can deserialize gnark-generated public keys', async () => {
      const gnarkOp = makeGnarkOPRFOperator({...})
      const stwoOp = makeStwoOPRFOperator({...})

      // Generate keys with gnark
      const keys = await gnarkOp.generateThresholdKeys(3, 2)

      // Verify stwo can parse the public key format
      const pubKeyHex = Buffer.from(keys.publicKey).toString('hex')
      expect(pubKeyHex.length).toBe(128) // 64 bytes

      // Stwo should be able to work with this format
      // (Even though outputs differ, parsing should work)
    })

    // Test: stwo generates keys, gnark evaluates
    it('gnark can deserialize stwo-generated public keys')
  })

  // === Hash Output Non-Compatibility Documentation ===

  describe('hash output differences (expected)', () => {
    it('gnark and stwo produce different outputs for same input', async () => {
      const secret = 'test@email.com'
      const domain = 'reclaim'

      // Both systems with same secret
      const gnarkOutput = await runGnarkTOPRF(secret, domain)
      const stwoOutput = await runStwoTOPRF(secret, domain)

      // Outputs SHOULD be different (different hash functions)
      expect(gnarkOutput).not.toEqual(stwoOutput)

      // But both should be valid (non-zero, deterministic)
      expect(gnarkOutput.length).toBeGreaterThan(0)
      expect(stwoOutput.length).toBeGreaterThan(0)
    })
  })
})
```

## Phase 4: ZK Proof Tests (Cipher + TOPRF)

### 4.1 Full Prove/Verify Workflow

Test the complete ZK workflow with stwo:

```typescript
describe('stwo cipher+TOPRF ZK proofs', () => {

  for (const algorithm of ['chacha20', 'aes-128-ctr', 'aes-256-ctr']) {
    describe(`${algorithm} + TOPRF`, () => {

      it('should generate and verify proof with TOPRF at pos=0')
      it('should generate and verify proof with TOPRF at pos=10')
      it('should handle multi-block TOPRF')
      it('should handle TOPRF spanning block boundaries')

      // Benchmark
      it('should complete prove+verify within acceptable time')
    })
  }
})
```

### 4.2 Test Matrix Update

Update the existing test matrix to include stwo:

```typescript
// In lib.test.ts - ensure stwo is tested for basic cipher proofs
const TEST_MATRIX = [
  { engine: 'gnark', algorithms: [...] },
  { engine: 'snarkjs', algorithms: [...] },
  { engine: 'stwo', algorithms: [...] },
]

// In oprf.test.ts - add stwo TOPRF
const OPRF_ZK_ENGINES_MAP = {
  'gnark': { ... },
  'stwo': { ... },  // NEW
}
```

## Phase 5: Benchmark Tests

### 5.1 Create `js/src/tests/toprf-benchmark.ts`

Performance comparison:

```typescript
describe('TOPRF benchmarks', () => {

  it('benchmark gnark TOPRF key generation')
  it('benchmark stwo TOPRF key generation')

  it('benchmark gnark TOPRF evaluation')
  it('benchmark stwo TOPRF evaluation')

  it('benchmark gnark TOPRF finalization')
  it('benchmark stwo TOPRF finalization')

  it('benchmark full gnark cipher+TOPRF proof')
  it('benchmark full stwo cipher+TOPRF proof')
})
```

## Implementation Order

### Week 1: Stwo TOPRF Operator

1. [ ] Create `js/src/stwo/toprf.ts` with `makeStwoOPRFOperator`
2. [ ] Update `js/src/stwo/s2circuits.d.ts` with TOPRF declarations
3. [ ] Copy updated WASM files to resources
4. [ ] Write basic unit tests for stwo TOPRF operator

### Week 2: Integration Tests

5. [ ] Update `oprf.test.ts` to include stwo in test matrix
6. [ ] Run existing OPRF tests with stwo operator
7. [ ] Fix any integration issues

### Week 3: Cross-Compatibility Tests

8. [ ] Create `toprf-compat.test.ts`
9. [ ] Test serialization format compatibility
10. [ ] Test curve operation compatibility
11. [ ] Document expected differences

### Week 4: Full System Tests + Benchmarks

12. [ ] Test full cipher+TOPRF workflow
13. [ ] Add benchmark tests
14. [ ] Update documentation

## Test File Structure

```
js/src/tests/
├── lib.test.ts           # Basic cipher tests (gnark, snarkjs, stwo)
├── oprf.test.ts          # TOPRF tests (gnark, stwo) - UPDATE
├── stwo-toprf.test.ts    # NEW: Stwo TOPRF unit tests
├── toprf-compat.test.ts  # NEW: Cross-compatibility tests
├── toprf-benchmark.ts    # NEW: Performance benchmarks
├── benchmark.ts          # Existing benchmarks
├── setup.ts              # Test setup
└── utils.ts              # Test utilities
```

## Expected Test Output

```
stwo TOPRF basic tests
  ✓ should generate threshold keys (50ms)
  ✓ should create OPRF request (20ms)
  ✓ should evaluate OPRF (100ms)
  ✓ should finalize TOPRF (150ms)
  ✓ should handle max secret size (180ms)

gnark-stwo TOPRF compatibility tests
  serialization format
    ✓ points serialize to 64 bytes hex
    ✓ JSON structures match
  curve operations
    ✓ gnark keys parseable by stwo
    ✓ stwo keys parseable by gnark
  hash output differences
    ✓ gnark and stwo outputs differ (expected)

stwo - chacha20 TOPRF circuits Tests
  ✓ should prove & verify TOPRF at pos=0 (5000ms)
  ✓ should prove & verify TOPRF at pos=10 (5000ms)
  ✓ should prove OPRF spread across blocks (8000ms)

gnark - chacha20 TOPRF circuits Tests
  ✓ should prove & verify TOPRF at pos=0 (2000ms)
  ...
```

## Notes

### Why Outputs Differ

The TOPRF output is computed as:
```
output = Hash(unmasked_point.x, unmasked_point.y, secret[0], secret[1])
```

- **Gnark**: `Hash = MiMC_BN254` (256-bit output)
- **Stwo**: `Hash = Poseidon2_M31` (31-bit output)

This is by design - each system uses the hash function native to its constraint system for efficiency.

### What IS Compatible

1. **Key format**: Same Baby Jubjub curve, same serialization
2. **Request format**: Same JSON structure
3. **DLEQ structure**: Same (c, r) tuple format
4. **Threshold scheme**: Same Lagrange interpolation

### What is NOT Compatible

1. **Hash-to-curve**: Different hash functions
2. **Final output**: Different hash functions
3. **DLEQ challenge computation**: Uses hash function

### Security Note

Both implementations provide the same security guarantees:
- OPRF blindness (server learns nothing about input)
- Verifiability (DLEQ proves correct evaluation)
- Threshold security (t-of-n reconstruction)

The difference is only in the algebraic details, not the security model.
