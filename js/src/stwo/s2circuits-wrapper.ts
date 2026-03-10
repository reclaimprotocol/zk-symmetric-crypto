/**
 * ESM wrapper for the CommonJS s2circuits module
 */
import { createRequire } from 'module'
import { dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)

// Load the CommonJS module
const s2circuits = require('./s2circuits.cjs')

// Re-export all functions
export const bench_toprf_native = s2circuits.bench_toprf_native
export const debug_chacha20_keystream = s2circuits.debug_chacha20_keystream
export const generate_aes128_ctr_proof = s2circuits.generate_aes128_ctr_proof
export const generate_aes256_ctr_proof = s2circuits.generate_aes256_ctr_proof
export const generate_chacha20_proof = s2circuits.generate_chacha20_proof
export const get_circuits_info = s2circuits.get_circuits_info
export const get_toprf_info = s2circuits.get_toprf_info
export const prove_aes128_ctr_encrypt = s2circuits.prove_aes128_ctr_encrypt
export const prove_aes256_ctr_encrypt = s2circuits.prove_aes256_ctr_encrypt
export const prove_chacha20_encrypt = s2circuits.prove_chacha20_encrypt
export const toprf_create_request = s2circuits.toprf_create_request
export const toprf_evaluate = s2circuits.toprf_evaluate
export const toprf_finalize = s2circuits.toprf_finalize
export const toprf_generate_keys = s2circuits.toprf_generate_keys
export const debug_dleq_hash = s2circuits.debug_dleq_hash
export const debug_dleq_verify = s2circuits.debug_dleq_verify
export const verify_aes_ctr_proof = s2circuits.verify_aes_ctr_proof
export const verify_chacha20_proof = s2circuits.verify_chacha20_proof

// For init compatibility (nodejs target auto-initializes)
export function initSync(_options?: unknown): unknown {
	// WASM already initialized by nodejs target
	return {}
}

export default s2circuits
