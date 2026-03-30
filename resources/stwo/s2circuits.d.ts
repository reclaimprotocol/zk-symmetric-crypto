/* tslint:disable */
/* eslint-disable */

/**
 * Debug: compute ChaCha20 keystream and return it (for debugging WASM issues).
 */
export function debug_chacha20_keystream(key: Uint8Array, nonce: Uint8Array, counter: number): string;

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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly prove_chacha20_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly prove_aes128_ctr_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly prove_aes256_ctr_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly generate_chacha20_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly verify_chacha20_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly generate_aes128_ctr_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly generate_aes256_ctr_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly verify_aes_ctr_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
    readonly debug_chacha20_keystream: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly get_circuits_info: () => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
