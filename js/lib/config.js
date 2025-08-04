"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONFIG = exports.GIT_COMMIT_HASH = void 0;
const chacha20poly1305_1 = require("@stablelib/chacha20poly1305");
const utils_1 = require("./utils");
const webcrypto_1 = require("./webcrypto");
const { subtle } = webcrypto_1.webcrypto;
// commit hash for this repo
exports.GIT_COMMIT_HASH = '2fcb282deb2b994a3ea4dd9039630ce2f94df8bf';
exports.CONFIG = {
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
        uint8ArrayToBits: (arr) => ((0, utils_1.uintArrayToBits)((0, utils_1.toUintArray)(arr)).flat()),
        bitsToUint8Array: (bits) => {
            const arr = (0, utils_1.bitsToUintArray)(bits);
            return (0, utils_1.toUint8Array)(arr);
        },
        encrypt({ key, iv, in: data }) {
            const cipher = new chacha20poly1305_1.ChaCha20Poly1305(key);
            const ciphertext = cipher.seal(iv, data);
            return ciphertext.slice(0, data.length);
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
        uint8ArrayToBits: utils_1.uint8ArrayToBits,
        bitsToUint8Array: utils_1.bitsToUint8Array,
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
        uint8ArrayToBits: utils_1.uint8ArrayToBits,
        bitsToUint8Array: utils_1.bitsToUint8Array,
        encrypt: makeAesCtr(128),
    },
};
function makeAesCtr(keyLenBits) {
    return async ({ key, iv, in: inp }) => {
        const keyImp = await subtle.importKey('raw', key, { name: 'AES-GCM', length: keyLenBits }, false, ['encrypt']);
        const buff = await subtle.encrypt({ name: 'AES-GCM', iv }, keyImp, inp);
        return new Uint8Array(buff).slice(0, inp.length);
    };
}
