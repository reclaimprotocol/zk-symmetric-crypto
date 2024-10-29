import { CONFIG } from './config'
import { EncryptionAlgorithm, UintArray } from './types'

export const BITS_PER_WORD = 32

// we use this to pad the ciphertext
export const REDACTION_CHAR_CODE = '*'.charCodeAt(0)

export function toUintArray(buf: Uint8Array) {
	const arr = makeUintArray(buf.length / 4)
	const arrView = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
	for(let i = 0;i < arr.length;i++) {
		arr[i] = arrView.getUint32(i * 4, true)
	}

	return arr
}

export function makeUintArray(init: number | number[]) {
	return typeof init === 'number'
		? new Uint32Array(init)
		: Uint32Array.from(init)
}

/**
 * Convert a UintArray (uint32array) to a Uint8Array
 */
export function toUint8Array(buf: UintArray) {
	const arr = new Uint8Array(buf.length * 4)
	const arrView = new DataView(arr.buffer, arr.byteOffset, arr.byteLength)
	for(const [i, element] of buf.entries()) {
		arrView.setUint32(i * 4, element, true)
	}

	return arr
}


export function padU8ToU32Array(buf: Uint8Array): Uint8Array {

	if(buf.length % 4 === 0) {
		return buf
	}

	return makeUint8Array(
		[
			...Array.from(buf),
			...new Array(4 - buf.length % 4).fill(REDACTION_CHAR_CODE)
		]
	)
}

export function makeUint8Array(init: number | number[]) {
	return typeof init === 'number'
		? new Uint8Array(init)
		: Uint8Array.from(init)
}

export function padArray(buf: UintArray, size: number): UintArray {
	return makeUintArray(
		[
			...Array.from(buf),
			...new Array(size - buf.length).fill(REDACTION_CHAR_CODE)
		]
	)
}

/**
 * Converts a Uint8Array to an array of bits.
 * BE order.
 */
export function uint8ArrayToBits(buff: Uint8Array | number[]) {
	const res: number[] = []
	for(const element of buff) {
		for(let j = 0; j < 8; j++) {
			if((element >> 7 - j) & 1) {
				res.push(1)
			} else {
				res.push(0)
			}
		}
	}

	return res
}

/**
 * Converts an array of bits to a Uint8Array.
 * Expecting BE order.
 * @param bits
 * @returns
 */
export function bitsToUint8Array(bits: number[]) {
	const arr = new Uint8Array(bits.length / 8)
	for(let i = 0;i < bits.length;i += 8) {
		const uint = bitsToNum(bits.slice(i, i + 8))
		arr[i / 8] = uint
	}

	return arr
}

/**
 * Converts a Uint32Array to an array of bits.
 * LE order.
 */
export function uintArrayToBits(uintArray: UintArray | number[]) {
	const bits: number[][] = []
	for(const uint of uintArray) {
		bits.push(numToBitsNumerical(uint))
	}

	return bits
}

export function bitsToUintArray(bits: number[]) {
	const uintArray = new Uint32Array(bits.length / BITS_PER_WORD)
	for(let i = 0;i < bits.length;i += BITS_PER_WORD) {
		const uint = bitsToNum(bits.slice(i, i + BITS_PER_WORD))
		uintArray[i / BITS_PER_WORD] = uint
	}

	return uintArray
}

function numToBitsNumerical(num: number, bitCount = BITS_PER_WORD) {
	const bits: number[] = []
	for(let i = 2 ** (bitCount - 1);i >= 1;i /= 2) {
		const bit = num >= i ? 1 : 0
		bits.push(bit)
		num -= bit * i
	}

	return bits
}

function bitsToNum(bits: number[]) {
	let num = 0

	let exp = 2 ** (bits.length - 1)
	for(const bit of bits) {
		num += bit * exp
		exp /= 2
	}

	return num
}

/**
 * Combines a 12 byte nonce with a 4 byte counter
 * to make a 16 byte IV.
 */
export function getFullCounterIv(nonce: Uint8Array, counter: number) {
	const iv = Buffer.alloc(16)
	iv.set(nonce, 0)
	iv.writeUInt32BE(counter, 12)

	return iv
}

/**
 * Get the counter to use for a given chunk.
 * @param algorithm
 * @param offsetInChunks
 * @returns
 */
export function getCounterForChunk(
	algorithm: EncryptionAlgorithm,
	offsetInChunks: number
) {
	const { startCounter, blocksPerChunk } = CONFIG[algorithm]
	return startCounter + offsetInChunks * blocksPerChunk
}