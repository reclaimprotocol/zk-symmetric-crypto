"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const index_1 = require("../index");
const utils_1 = require("./utils");
jest.setTimeout(100_000);
// TODO: add back AES tests
const ALL_ALGOS = [
    'chacha20',
    'aes-256-ctr',
    'aes-128-ctr',
];
const SUPPORTED_ALGO_MAP = {
    // TODO: impl more algos for barretenberg
    // barretenberg: ['aes-256-ctr', 'aes-128-ctr'],
    barretenberg: ['aes-128-ctr', 'chacha20'],
    expander: ['chacha20'],
    gnark: ALL_ALGOS,
    snarkjs: ALL_ALGOS,
};
const ALG_TEST_CONFIG = {
    'chacha20': {
        encLength: 45,
    },
    'aes-256-ctr': {
        encLength: 44,
    },
    'aes-128-ctr': {
        encLength: 44,
    },
};
describe.each(utils_1.ZK_CONFIGS)('%s Engine Tests', (zkEngine) => {
    const ALGOS = SUPPORTED_ALGO_MAP[(0, utils_1.getEngineForConfigItem)(zkEngine)];
    describe.each(ALGOS)('%s Lib Tests', (algorithm) => {
        const { encLength } = ALG_TEST_CONFIG[algorithm];
        const { bitsPerWord, chunkSize, keySizeBytes } = index_1.CONFIG[algorithm];
        const chunkSizeBytes = chunkSize * bitsPerWord / 8;
        let operator;
        beforeAll(async () => {
            operator = await utils_1.ZK_CONFIG_MAP[zkEngine](algorithm);
        });
        afterEach(async () => {
            await operator.release?.();
        });
        it('should verify encrypted data', async () => {
            const plaintext = new Uint8Array((0, crypto_1.randomBytes)(encLength));
            const privateInput = {
                key: Buffer.alloc(keySizeBytes, 2),
            };
            const iv = new Uint8Array(Array.from(Array(12).keys()));
            const ciphertext = (0, utils_1.encryptData)(algorithm, plaintext, privateInput.key, iv);
            const publicInput = { ciphertext, iv: iv };
            const proof = await (0, index_1.generateProof)({
                algorithm,
                privateInput,
                publicInput,
                operator,
            });
            // client will send proof to witness
            // witness would verify proof
            await (0, index_1.verifyProof)({ proof, publicInput, operator });
        });
        it('should verify encrypted with static plaintext', async () => {
            // 76,  97, 100, 105, 101, 115,  32,  97,
            // 110, 100,  32,  71, 101, 110, 116, 108,
            // 101, 109, 101, 110,  32, 111, 102,  32,
            // 116, 104, 101,  32,  99, 108,  97, 115,
            // 115,  32, 111, 102
            const text = 'Ladies and Gentlemen of the class of';
            const plaintext = Uint8Array.from(text.split('').map(char => char.charCodeAt(0)));
            const privateInput = {
                key: Buffer.alloc(keySizeBytes, 2),
            };
            const iv = new Uint8Array(Array.from(Array(12).keys()));
            const ciphertext = (0, utils_1.encryptData)(algorithm, plaintext, privateInput.key, iv);
            const publicInput = { ciphertext, iv: iv };
            const proof = await (0, index_1.generateProof)({
                algorithm,
                privateInput,
                publicInput,
                operator,
            });
            // client will send proof to witness
            // witness would verify proof
            await (0, index_1.verifyProof)({ proof, publicInput, operator });
        });
        it('should verify encrypted data with another counter', async () => {
            const totalPlaintext = new Uint8Array((0, crypto_1.randomBytes)(chunkSizeBytes * 5));
            // use two blocks as offset (not chunks)
            const offsetBytes = 2 * (0, index_1.getBlockSizeBytes)(algorithm);
            const iv = Buffer.alloc(12, 3);
            const privateInput = {
                key: Buffer.alloc(keySizeBytes, 2),
            };
            const totalCiphertext = (0, utils_1.encryptData)(algorithm, totalPlaintext, privateInput.key, iv);
            const ciphertext = totalCiphertext.subarray(offsetBytes, chunkSizeBytes + offsetBytes);
            const publicInput = { ciphertext, iv, offsetBytes };
            const proof = await (0, index_1.generateProof)({
                algorithm,
                privateInput,
                publicInput,
                operator,
            });
            await (0, index_1.verifyProof)({ proof, publicInput, operator });
        });
        it('should fail to verify incorrect data', async () => {
            const plaintext = Buffer.alloc(encLength, 1);
            const privateInput = {
                key: Buffer.alloc(keySizeBytes, 2),
            };
            const iv = Buffer.alloc(12, 3);
            const ciphertext = (0, utils_1.encryptData)(algorithm, plaintext, privateInput.key, iv);
            const publicInput = { ciphertext, iv };
            const proof = await (0, index_1.generateProof)({
                algorithm,
                privateInput,
                publicInput,
                operator,
            });
            if (zkEngine === 'barretenberg') {
                proof.proofData[0] = (proof.proofData[0] + 1) % 256;
            }
            else {
                for (let i = 0; i < proof.plaintext.length; i++) {
                    proof.plaintext[i] = 0;
                }
            }
            await expect((0, index_1.verifyProof)({ proof, publicInput, operator })).rejects.toHaveProperty('message', 'invalid proof');
        });
    });
});
