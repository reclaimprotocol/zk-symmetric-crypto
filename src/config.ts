import { bitsToUint8Array, bitsToUintArray, toUint8Array, toUintArray, uint8ArrayToBits, uintArrayToBits } from "./utils"
import { EncryptionConfig } from "./types"

 const createEncryptionConfig = (config: Partial<EncryptionConfig>): EncryptionConfig => {
    return {
        chunkSize: config.chunkSize ?? 64,
        bitsPerWord: config.bitsPerWord ?? 8,
        keySizeBytes: config.keySizeBytes ?? 32,
        ivSizeBytes: config.ivSizeBytes ?? 12,
        startCounter: config.startCounter ?? 1,
        blocksPerChunk: config.blocksPerChunk ?? 1,
        isLittleEndian: config.isLittleEndian ?? false,
        uint8ArrayToBits: config.uint8ArrayToBits ?? ((arr: Uint8Array) => uintArrayToBits(toUintArray(arr))),
        bitsToUint8Array: config.bitsToUint8Array ?? ((bits: number[]) => toUint8Array(bitsToUintArray(bits))),
    };
};


export const chacha20Config = createEncryptionConfig({
    chunkSize: 16,
    bitsPerWord: 32,
    keySizeBytes: 32,
    ivSizeBytes: 12,
    startCounter: 1,
    blocksPerChunk: 1,
    isLittleEndian: true,
    uint8ArrayToBits: (arr: Uint8Array) => uintArrayToBits(toUintArray(arr)),
    bitsToUint8Array: (bits: number[]) => toUint8Array(bitsToUintArray(bits)),
});

export const aes256CtrConfig = createEncryptionConfig({
    chunkSize: 64,
    bitsPerWord: 8,
    keySizeBytes: 32,
    ivSizeBytes: 12,
    startCounter: 2,
    blocksPerChunk: 4,
    isLittleEndian: false,
    uint8ArrayToBits,
    bitsToUint8Array,
});

export const aes128CtrConfig = createEncryptionConfig({
    chunkSize: 64,
    bitsPerWord: 8,
    keySizeBytes: 16,
    ivSizeBytes: 12,
    startCounter: 2,
    blocksPerChunk: 4,
    isLittleEndian: false,
    uint8ArrayToBits,
    bitsToUint8Array,
});

export const CONFIG = {
    'chacha20': chacha20Config,
    'aes-256-ctr': aes256CtrConfig,
    'aes-128-ctr': aes128CtrConfig,
};