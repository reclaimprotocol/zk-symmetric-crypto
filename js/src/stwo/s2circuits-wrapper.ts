/**
 * ESM wrapper for the CommonJS s2circuits module
 */
import { createRequire } from 'module'

const require = createRequire(import.meta.url)

// Load the CommonJS module
// eslint-disable-next-line @typescript-eslint/no-require-imports
const s2circuits = require('./s2circuits.cjs')

// Re-export cipher functions only
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
export const prove_aes128_ctr_encrypt = s2circuits.prove_aes128_ctr_encrypt
// eslint-disable-next-line camelcase
export const prove_aes256_ctr_encrypt = s2circuits.prove_aes256_ctr_proof
// eslint-disable-next-line camelcase
export const prove_chacha20_encrypt = s2circuits.prove_chacha20_encrypt
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
