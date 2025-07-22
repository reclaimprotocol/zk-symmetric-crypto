import { CONFIG } from '../config'
import { EncryptionAlgorithm, ZKProofInput } from '../types'
import { NoirWitnessInput } from './types'


/**
 * Convert ZKProofInput to Noir witness format
 * Noir expects byte arrays for AES-256-CTR
 */
export function convertToNoirWitness(
	algorithm: EncryptionAlgorithm,
	input: ZKProofInput
): NoirWitnessInput {
	if(algorithm === 'chacha20') {
		// ChaCha20 is not implemented in Noir yet
		throw new Error('ChaCha20 is not implemented in Noir circuits')
	}

	const { chunkSize, bitsPerWord } = CONFIG[algorithm]
	const expectedSizeBytes = (chunkSize * bitsPerWord) / 8

	// For AES-CTR, construct the full 16-byte counter from nonce + counter
	// Counter format: 12 bytes nonce + 4 bytes counter (big-endian)
	const fullCounter = new Uint8Array(16)
	fullCounter.set(input.nonce, 0) // First 12 bytes are the nonce

	// Convert the counter number to 4 bytes (big-endian)
	const counterBytes = new Uint8Array(4)
	counterBytes[0] = (input.counter >> 24) & 0xff
	counterBytes[1] = (input.counter >> 16) & 0xff
	counterBytes[2] = (input.counter >> 8) & 0xff
	counterBytes[3] = input.counter & 0xff

	fullCounter.set(counterBytes, 12) // Last 4 bytes are the counter

	// For Noir circuits, we only process the first 16 bytes (1 AES block)
	// The input may be padded to 80 bytes (5 blocks) but Noir only expects 1 block

	// Convert Uint8Arrays to regular arrays for Noir
	const keyArray = Array.from(input.key)
	const counterArray = Array.from(fullCounter)
	const plaintextArray = Array.from(input.in)
	const expectedCiphertextArray = Array.from(input.out)

	// Validate key size based on algorithm
	if(algorithm === 'aes-256-ctr' && keyArray.length !== 32) {
		throw new Error(`Invalid key size for AES-256-CTR: expected 32 bytes, got ${keyArray.length}`)
	} else if(algorithm === 'aes-128-ctr' && keyArray.length !== 16) {
		throw new Error(`Invalid key size for AES-128-CTR: expected 16 bytes, got ${keyArray.length}`)
	}

	// Validate block sizes
	if(plaintextArray.length !== expectedSizeBytes) {
		throw new Error(`Invalid plaintext size: expected ${expectedSizeBytes} bytes, got ${plaintextArray.length}`)
	}

	if(expectedCiphertextArray.length !== expectedSizeBytes) {
		throw new Error(`Invalid ciphertext size: expected ${expectedSizeBytes} bytes, got ${expectedCiphertextArray.length}`)
	}

	// For AES, the Noir circuit expects:
	// - key: [u8; 32] for AES-256 or [u8; 16] for AES-128
	// - counter: [u8; 16] (nonce + counter)
	// - plaintext: [u8; 16]
	// - expected_ciphertext: [u8; 16]
	return {
		key: keyArray,
		counter: counterArray,
		plaintext: plaintextArray,
		// eslint-disable-next-line camelcase
		expected_ciphertext: expectedCiphertextArray
		// NOTE: operator.groth16Prove(wtnsSerialised, logger) needs literal `expected_ciphertext` for generate proof
	}
}

/**
 * Get the circuit filename for the algorithm
 */
export function getCircuitFilename(algorithm: EncryptionAlgorithm): string {
	switch (algorithm) {
	case 'aes-128-ctr':
		return 'aes_128_ctr.json'
	case 'aes-256-ctr':
		return 'aes_256_ctr.json'
	case 'chacha20':
		throw new Error('ChaCha20 is not implemented in Noir circuits')
	default:
		throw new Error(`Unknown algorithm: ${algorithm}`)
	}
}