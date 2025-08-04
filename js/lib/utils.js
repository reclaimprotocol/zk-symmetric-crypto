"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.REDACTION_CHAR_CODE = exports.BITS_PER_WORD = void 0;
exports.toUintArray = toUintArray;
exports.makeUintArray = makeUintArray;
exports.toUint8Array = toUint8Array;
exports.padU8ToU32Array = padU8ToU32Array;
exports.makeUint8Array = makeUint8Array;
exports.padArray = padArray;
exports.uint8ArrayToBits = uint8ArrayToBits;
exports.bitsToUint8Array = bitsToUint8Array;
exports.uintArrayToBits = uintArrayToBits;
exports.bitsToUintArray = bitsToUintArray;
exports.serialiseValuesToBits = serialiseValuesToBits;
exports.serialiseNumberTo4Bytes = serialiseNumberTo4Bytes;
exports.getFullCounterIv = getFullCounterIv;
exports.getCounterForByteOffset = getCounterForByteOffset;
exports.getBlockSizeBytes = getBlockSizeBytes;
const config_1 = require("./config");
exports.BITS_PER_WORD = 32;
// we use this to pad the ciphertext
exports.REDACTION_CHAR_CODE = '*'.charCodeAt(0);
function toUintArray(buf) {
    const arr = makeUintArray(buf.length / 4);
    const arrView = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    for (let i = 0; i < arr.length; i++) {
        arr[i] = arrView.getUint32(i * 4, true);
    }
    return arr;
}
function makeUintArray(init) {
    return typeof init === 'number'
        ? new Uint32Array(init)
        : Uint32Array.from(init);
}
/**
 * Convert a UintArray (uint32array) to a Uint8Array
 */
function toUint8Array(buf) {
    const arr = new Uint8Array(buf.length * 4);
    const arrView = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    for (const [i, element] of buf.entries()) {
        arrView.setUint32(i * 4, element, true);
    }
    return arr;
}
function padU8ToU32Array(buf) {
    if (buf.length % 4 === 0) {
        return buf;
    }
    return makeUint8Array([
        ...Array.from(buf),
        ...new Array(4 - buf.length % 4).fill(exports.REDACTION_CHAR_CODE)
    ]);
}
function makeUint8Array(init) {
    return typeof init === 'number'
        ? new Uint8Array(init)
        : Uint8Array.from(init);
}
function padArray(buf, size) {
    return makeUintArray([
        ...Array.from(buf),
        ...new Array(size - buf.length).fill(exports.REDACTION_CHAR_CODE)
    ]);
}
/**
 * Converts a Uint8Array to an array of bits.
 * BE order.
 */
function uint8ArrayToBits(buff) {
    const res = [];
    for (const element of buff) {
        for (let j = 0; j < 8; j++) {
            if ((element >> 7 - j) & 1) {
                res.push(1);
            }
            else {
                res.push(0);
            }
        }
    }
    return res;
}
/**
 * Converts an array of bits to a Uint8Array.
 * Expecting BE order.
 * @param bits
 * @returns
 */
function bitsToUint8Array(bits) {
    const arr = new Uint8Array(bits.length / 8);
    for (let i = 0; i < bits.length; i += 8) {
        arr[i / 8] = bitsToNum(bits.slice(i, i + 8));
    }
    return arr;
}
/**
 * Converts a Uint32Array to an array of bits.
 * LE order.
 */
function uintArrayToBits(uintArray) {
    const bits = [];
    for (const uint of uintArray) {
        bits.push(numToBitsNumerical(uint));
    }
    return bits;
}
function bitsToUintArray(bits) {
    const uintArray = new Uint32Array(bits.length / exports.BITS_PER_WORD);
    for (let i = 0; i < bits.length; i += exports.BITS_PER_WORD) {
        uintArray[i / exports.BITS_PER_WORD] = bitsToNum(bits.slice(i, i + exports.BITS_PER_WORD));
    }
    return uintArray;
}
function serialiseValuesToBits(algorithm, ...data) {
    const { uint8ArrayToBits } = config_1.CONFIG[algorithm];
    const bits = [];
    for (const element of data) {
        if (typeof element === 'number') {
            bits.push(...serialiseNumberToBits(algorithm, element));
        }
        else {
            bits.push(...uint8ArrayToBits(element));
        }
    }
    return bits;
}
function serialiseNumberToBits(algorithm, num) {
    const { uint8ArrayToBits, isLittleEndian } = config_1.CONFIG[algorithm];
    const counterArr = new Uint8Array(4);
    const counterView = new DataView(counterArr.buffer);
    counterView.setUint32(0, num, isLittleEndian);
    return uint8ArrayToBits(serialiseNumberTo4Bytes(algorithm, num))
        .flat();
}
function serialiseNumberTo4Bytes(algorithm, num) {
    const { isLittleEndian } = config_1.CONFIG[algorithm];
    const counterArr = new Uint8Array(4);
    const counterView = new DataView(counterArr.buffer);
    counterView.setUint32(0, num, isLittleEndian);
    return counterArr;
}
function numToBitsNumerical(num, bitCount = exports.BITS_PER_WORD) {
    const bits = [];
    for (let i = 2 ** (bitCount - 1); i >= 1; i /= 2) {
        const bit = num >= i ? 1 : 0;
        bits.push(bit);
        num -= bit * i;
    }
    return bits;
}
function bitsToNum(bits) {
    let num = 0;
    let exp = 2 ** (bits.length - 1);
    for (const bit of bits) {
        num += bit * exp;
        exp /= 2;
    }
    return num;
}
/**
 * Combines a 12 byte nonce with a 4 byte counter
 * to make a 16 byte IV.
 */
function getFullCounterIv(nonce, counter) {
    const iv = Buffer.alloc(16);
    iv.set(nonce, 0);
    iv.writeUInt32BE(counter, 12);
    return iv;
}
/**
 * Get the counter to use for a given chunk.
 * @param algorithm
 * @param offsetInChunks
 * @returns
 */
function getCounterForByteOffset(algorithm, offsetInBytes) {
    const { startCounter } = config_1.CONFIG[algorithm];
    const blockSizeBytes = getBlockSizeBytes(algorithm);
    if (offsetInBytes % blockSizeBytes !== 0) {
        throw new Error(`offset(${offsetInBytes}) must be a multiple of `
            + `block size(${blockSizeBytes})`);
    }
    return startCounter + (offsetInBytes / blockSizeBytes);
}
/**
 * get the block size of the cipher block in bytes
 * eg. chacha20 is 64 bytes, aes is 16 bytes
 */
function getBlockSizeBytes(alg) {
    const { chunkSize, bitsPerWord, blocksPerChunk } = config_1.CONFIG[alg];
    return chunkSize * bitsPerWord / (8 * blocksPerChunk);
}
