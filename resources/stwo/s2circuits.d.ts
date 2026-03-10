/* tslint:disable */
/* eslint-disable */

/**
 * Benchmark native TOPRF verification (no ZK proof, just the crypto operations).
 *
 * This measures the time for scalar multiplications, hashing, etc.
 * Returns JSON with timing info.
 */
export function bench_toprf_native(secret_bytes: Uint8Array, domain_separator: number): string;

/**
 * Debug: compute ChaCha20 keystream and return it (for debugging WASM issues).
 */
export function debug_chacha20_keystream(key: Uint8Array, nonce: Uint8Array, counter: number): string;

/**
 * Debug DLEQ verification - returns detailed info about hash computation.
 */
export function debug_dleq_hash(points_json: string): string;

/**
 * Debug DLEQ verification step by step.
 */
export function debug_dleq_verify(params_json: string): string;

/**
 * Generate AES-128-CTR proof and return it serialized (base64).
 */
export function generate_aes128_ctr_proof(key: Uint8Array, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array): string;

/**
 * Generate AES-256-CTR proof and return it serialized (base64).
 */
export function generate_aes256_ctr_proof(key: Uint8Array, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array): string;

/**
 * Generate ChaCha20 proof and return it serialized (base64).
 * Use verify_chacha20_proof() to verify the proof separately.
 */
export function generate_chacha20_proof(key: Uint8Array, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array): string;

/**
 * Get circuit information as JSON.
 */
export function get_circuits_info(): string;

/**
 * Get TOPRF circuit info.
 */
export function get_toprf_info(): string;

/**
 * Prove AES-128-CTR encryption.
 *
 * # Arguments
 * * `key` - 16-byte key (Uint8Array) - PRIVATE
 * * `nonce` - 12-byte nonce (Uint8Array) - PUBLIC
 * * `counter` - Starting counter value - PUBLIC
 * * `plaintext` - Plaintext bytes (Uint8Array, must be multiple of 16) - PUBLIC
 * * `ciphertext` - Ciphertext bytes (Uint8Array, same length as plaintext) - PUBLIC
 *
 * # Returns
 * JSON string: {"success": true, "blocks": N} or {"error": "..."}
 *
 * # What the proof demonstrates
 * "I know a secret key K such that AES-128-CTR(K, nonce, counter, plaintext) = ciphertext"
 * The key remains private - the verifier learns nothing about it.
 */
export function prove_aes128_ctr_encrypt(key: Uint8Array, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array): string;

/**
 * Prove AES-256-CTR encryption.
 *
 * # Arguments
 * * `key` - 32-byte key (Uint8Array) - PRIVATE
 * * `nonce` - 12-byte nonce (Uint8Array) - PUBLIC
 * * `counter` - Starting counter value - PUBLIC
 * * `plaintext` - Plaintext bytes (Uint8Array, must be multiple of 16) - PUBLIC
 * * `ciphertext` - Ciphertext bytes (Uint8Array, same length as plaintext) - PUBLIC
 *
 * # Returns
 * JSON string: {"success": true, "blocks": N} or {"error": "..."}
 *
 * # What the proof demonstrates
 * "I know a secret key K such that AES-256-CTR(K, nonce, counter, plaintext) = ciphertext"
 * The key remains private - the verifier learns nothing about it.
 */
export function prove_aes256_ctr_encrypt(key: Uint8Array, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array): string;

/**
 * Prove ChaCha20 encryption.
 *
 * # Arguments
 * * `key` - 32-byte key (Uint8Array) - PRIVATE
 * * `nonce` - 12-byte nonce (Uint8Array) - PUBLIC
 * * `counter` - Starting counter value - PUBLIC
 * * `plaintext` - Plaintext bytes (Uint8Array, must be multiple of 64) - PUBLIC
 * * `ciphertext` - Ciphertext bytes (Uint8Array, same length as plaintext) - PUBLIC
 *
 * # Returns
 * JSON string: {"success": true, "blocks": N} or {"error": "..."}
 *
 * # What the proof demonstrates
 * "I know a secret key K such that ChaCha20(K, nonce, counter, plaintext) = ciphertext"
 * The key remains private - the verifier learns nothing about it.
 */
export function prove_chacha20_encrypt(key: Uint8Array, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array): string;

/**
 * Create OPRF request (client-side).
 *
 * # Arguments
 * * `secret_bytes` - Secret data to hash (max 62 bytes)
 * * `domain_separator` - Domain separator string
 *
 * # Returns
 * JSON string matching gnark's OPRFRequest format:
 * - mask: hex-encoded scalar
 * - maskedData: hex-encoded 64-byte point
 * - secretElements: [hex, hex] two field elements
 */
export function toprf_create_request(secret_bytes: Uint8Array, domain_separator: string): string;

/**
 * Evaluate OPRF (server-side).
 *
 * # Arguments
 * * `share_json` - JSON with share: { index, privateKey, publicKey }
 * * `masked_request_hex` - Hex-encoded 64-byte masked point
 *
 * # Returns
 * JSON string matching gnark's OPRFResponse format:
 * - index: share index
 * - publicKeyShare: hex-encoded 64-byte point
 * - evaluated: hex-encoded 64-byte point
 * - c: hex-encoded DLEQ challenge
 * - r: hex-encoded DLEQ response
 */
export function toprf_evaluate(share_json: string, masked_request_hex: string): string;

/**
 * Finalize TOPRF (client-side).
 *
 * # Arguments
 * * `params_json` - JSON matching gnark's InputTOPRFFinalizeParams:
 *   - serverPublicKey: hex-encoded 64-byte point
 *   - request: { mask, maskedData, secretElements }
 *   - responses: [{ index, publicKeyShare, evaluated, c, r }, ...]
 *
 * # Returns
 * JSON string with:
 * - output: hex-encoded hash output
 * - outputDecimal: decimal string of output (for comparison)
 */
export function toprf_finalize(params_json: string): string;

/**
 * Generate TOPRF shared keys for threshold scheme.
 *
 * # Arguments
 * * `nodes` - Total number of nodes
 * * `threshold` - Minimum nodes required to reconstruct
 *
 * # Returns
 * JSON string with:
 * - serverPublicKey: 64-byte hex-encoded point
 * - shares: Array of share objects with index, privateKey, publicKey
 */
export function toprf_generate_keys(nodes: number, threshold: number): string;

/**
 * Verify an AES-CTR proof (base64-encoded) against verifier-supplied public inputs.
 * Works for both AES-128 and AES-256.
 *
 * The verifier must provide the expected nonce, counter, plaintext, and ciphertext.
 * Verification fails if the proof was generated for different data.
 */
export function verify_aes_ctr_proof(proof_b64: string, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array): string;

/**
 * Verify a ChaCha20 proof (base64-encoded) against verifier-supplied public inputs.
 *
 * The verifier must provide the expected nonce, counter, plaintext, and ciphertext.
 * Verification fails if the proof was generated for different data.
 */
export function verify_chacha20_proof(proof_b64: string, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array): string;
