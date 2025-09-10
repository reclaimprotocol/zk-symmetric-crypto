import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305'
import { AlgorithmConfig, EncryptionAlgorithm } from './types'
import { bitsToUint8Array, bitsToUintArray, toUint8Array, toUintArray, uint8ArrayToBits, uintArrayToBits } from './utils'
import { webcrypto } from './webcrypto'

const { subtle } = webcrypto

// commit hash for this repo
export const GIT_COMMIT_HASH = '50b2f6297bc87796f3e22b821e02738be5d1425f'

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
		encrypt({ key, iv, in: data }) {
			const cipher = new ChaCha20Poly1305(key)
			const ciphertext = cipher.seal(iv, data)
			return ciphertext.slice(0, data.length)
		},
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
		encrypt: makeAesCtr(256),
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
		encrypt: makeAesCtr(128),
	},
}

function makeAesCtr(keyLenBits: number): AlgorithmConfig['encrypt'] {
	return async({ key, iv, in: inp }) => {
		const keyImp = await subtle.importKey(
			'raw', key,
			{ name: 'AES-GCM', length: keyLenBits },
			false,
			['encrypt']
		)
		const buff = await subtle.encrypt(
			{ name: 'AES-GCM', iv },
			keyImp,
			inp
		)
		return new Uint8Array(buff).slice(0, inp.length)
	}
}