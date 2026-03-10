/**
 * ESM wrapper for the CommonJS s2circuits module
 */
import { createRequire } from 'module'

const require = createRequire(import.meta.url)

// Load the CommonJS module
// eslint-disable-next-line @typescript-eslint/no-require-imports
const s2circuits = require('./s2circuits.cjs')

// Re-export all functions
// eslint-disable-next-line camelcase
export const bench_toprf_native = s2circuits.bench_toprf_native
// eslint-disable-next-line camelcase
export const debug_chacha20_keystream = s2circuits.debug_chacha20_keystream
// eslint-disable-next-line camelcase
export const generate_aes128_ctr_proof = s2circuits.generate_aes128_ctr_proof
// eslint-disable-next-line camelcase
export const generate_aes256_ctr_proof = s2circuits.generate_aes256_ctr_proof
// eslint-disable-next-line camelcase
export const generate_chacha20_proof = s2circuits.generate_chacha20_proof
// eslint-disable-next-line camelcase
export const get_circuits_info = s2circuits.get_circuits_info
// eslint-disable-next-line camelcase
export const get_toprf_info = s2circuits.get_toprf_info
// eslint-disable-next-line camelcase
export const prove_aes128_ctr_encrypt = s2circuits.prove_aes128_ctr_encrypt
// eslint-disable-next-line camelcase
export const prove_aes256_ctr_encrypt = s2circuits.prove_aes256_ctr_encrypt
// eslint-disable-next-line camelcase
export const prove_chacha20_encrypt = s2circuits.prove_chacha20_encrypt
// eslint-disable-next-line camelcase
export const toprf_create_request = s2circuits.toprf_create_request
// eslint-disable-next-line camelcase
export const toprf_evaluate = s2circuits.toprf_evaluate
// eslint-disable-next-line camelcase
export const toprf_finalize = s2circuits.toprf_finalize
// eslint-disable-next-line camelcase
export const toprf_generate_keys = s2circuits.toprf_generate_keys
// eslint-disable-next-line camelcase
export const debug_dleq_hash = s2circuits.debug_dleq_hash
// eslint-disable-next-line camelcase
export const debug_dleq_verify = s2circuits.debug_dleq_verify
// eslint-disable-next-line camelcase
export const verify_aes_ctr_proof = s2circuits.verify_aes_ctr_proof
// eslint-disable-next-line camelcase
export const verify_chacha20_proof = s2circuits.verify_chacha20_proof

// For init compatibility (nodejs target auto-initializes)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function initSync(options?: unknown): unknown {
	// WASM already initialized by nodejs target
	return {}
}

export default s2circuits
