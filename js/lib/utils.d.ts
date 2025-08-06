import { EncryptionAlgorithm, UintArray } from './types';
export declare const BITS_PER_WORD = 32;
export declare const REDACTION_CHAR_CODE: number;
export declare function toUintArray(buf: Uint8Array): Uint32Array;
export declare function makeUintArray(init: number | number[]): Uint32Array;
/**
 * Convert a UintArray (uint32array) to a Uint8Array
 */
export declare function toUint8Array(buf: UintArray): Uint8Array;
export declare function padU8ToU32Array(buf: Uint8Array): Uint8Array;
export declare function makeUint8Array(init: number | number[]): Uint8Array;
export declare function padArray(buf: UintArray, size: number): UintArray;
/**
 * Converts a Uint8Array to an array of bits.
 * BE order.
 */
export declare function uint8ArrayToBits(buff: Uint8Array | number[]): number[];
/**
 * Converts an array of bits to a Uint8Array.
 * Expecting BE order.
 * @param bits
 * @returns
 */
export declare function bitsToUint8Array(bits: number[]): Uint8Array;
/**
 * Converts a Uint32Array to an array of bits.
 * LE order.
 */
export declare function uintArrayToBits(uintArray: UintArray | number[]): number[][];
export declare function bitsToUintArray(bits: number[]): Uint32Array;
export declare function serialiseValuesToBits(algorithm: EncryptionAlgorithm, ...data: (Uint8Array | number)[]): number[];
export declare function serialiseNumberTo4Bytes(algorithm: EncryptionAlgorithm, num: number): Uint8Array;
/**
 * Combines a 12 byte nonce with a 4 byte counter
 * to make a 16 byte IV.
 */
export declare function getFullCounterIv(nonce: Uint8Array, counter: number): Buffer;
/**
 * Get the counter to use for a given chunk.
 * @param algorithm
 * @param offsetInChunks
 * @returns
 */
export declare function getCounterForByteOffset(algorithm: EncryptionAlgorithm, offsetInBytes: number): number;
/**
 * get the block size of the cipher block in bytes
 * eg. chacha20 is 64 bytes, aes is 16 bytes
 */
export declare function getBlockSizeBytes(alg: EncryptionAlgorithm): number;
