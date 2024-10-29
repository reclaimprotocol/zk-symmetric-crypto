import { bitsToUint8Array, bitsToUintArray, toUint8Array, toUintArray, uint8ArrayToBits, uintArrayToBits } from "./utils"

export const CONFIG = {
	'chacha20': {
		chunkSize: 16,
		bitsPerWord: 32,
		keySizeBytes: 32,
		ivSizeBytes: 12,
		startCounter: 1,
		// num of blocks per chunk
		blocksPerChunk: 1,
		// chacha20 circuit uses LE encoding
		isLittleEndian: true,
		uint8ArrayToBits: (arr: Uint8Array) => (
			uintArrayToBits(toUintArray(arr))
		),
		bitsToUint8Array: (bits: number[]) => {
			const arr = bitsToUintArray(bits)
			return toUint8Array(arr)
		},
	},
	'aes-256-ctr': {
		chunkSize: 64,
		bitsPerWord: 8,
		keySizeBytes: 32,
		ivSizeBytes: 12,
		startCounter: 2,
		// num of blocks per chunk
		blocksPerChunk: 4,
		// AES circuit uses BE encoding
		isLittleEndian: false,
		uint8ArrayToBits,
		bitsToUint8Array,
	},
	'aes-128-ctr': {
		chunkSize: 64,
		bitsPerWord: 8,
		keySizeBytes: 16,
		ivSizeBytes: 12,
		startCounter: 2,
		// num of blocks per chunk
		blocksPerChunk: 4,
		// AES circuit uses BE encoding
		isLittleEndian: false,
		uint8ArrayToBits,
		bitsToUint8Array,
	}
}