import { type AuthenticatedSymmetricCryptoAlgorithm, crypto } from '@reclaimprotocol/tls'
import type { AlgorithmConfig, EncryptionAlgorithm } from './types.ts'
import { bitsToUint8Array, bitsToUintArray, toUint8Array, toUintArray, uint8ArrayToBits, uintArrayToBits } from './utils.ts'

// commit hash for this repo
export const GIT_COMMIT_HASH = '4160642fd6c64c3f33c9144eaf8b4782c22ae2be'

export const CONFIG: { [E in EncryptionAlgorithm]: AlgorithmConfig } = {
	'chacha20': {
		index: 0,
		chunkSize: 32,
		bitsPerWord: 32,
		keySizeBytes: 32,
		ivSizeBytes: 12,
		startCounter: 1,
		// num of blocks per chunk
		blocksPerChunk: 2,
		// chacha20 circuit uses LE encoding
		isLittleEndian: true,
		uint8ArrayToBits: (arr: Uint8Array) => (
			uintArrayToBits(toUintArray(arr)).flat()
		),
		bitsToUint8Array: (bits: number[]) => {
			const arr = bitsToUintArray(bits)
			return toUint8Array(arr)
		},
		encrypt: makeAuthenticatedEncrypt('CHACHA20-POLY1305')
	},
	'aes-256-ctr': {
		index: 2,
		chunkSize: 80,
		bitsPerWord: 8,
		keySizeBytes: 32,
		ivSizeBytes: 12,
		startCounter: 2,
		// num of blocks per chunk
		blocksPerChunk: 5,
		// AES circuit uses BE encoding
		isLittleEndian: false,
		uint8ArrayToBits,
		bitsToUint8Array,
		encrypt: makeAuthenticatedEncrypt('AES-256-GCM')
	},
	'aes-128-ctr': {
		index: 1,
		chunkSize: 80,
		bitsPerWord: 8,
		keySizeBytes: 16,
		ivSizeBytes: 12,
		startCounter: 2,
		// num of blocks per chunk
		blocksPerChunk: 5,
		// AES circuit uses BE encoding
		isLittleEndian: false,
		uint8ArrayToBits,
		bitsToUint8Array,
		encrypt: makeAuthenticatedEncrypt('AES-128-GCM')
	},
}

function makeAuthenticatedEncrypt(
	alg: AuthenticatedSymmetricCryptoAlgorithm
): AlgorithmConfig['encrypt'] {
	return async({ key, iv, in: data }) => {
		const impKey = await crypto.importKey(alg, key)
		const { ciphertext } = await crypto.authenticatedEncrypt(alg, {
			key: impKey,
			iv,
			data,
			aead: new Uint8Array(0),
		})
		return ciphertext.slice(0, data.length)
	}
}