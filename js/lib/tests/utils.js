"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZK_CONFIGS = exports.ZK_CONFIG_MAP = void 0;
exports.encryptData = encryptData;
exports.loadCircuit = loadCircuit;
exports.getEngineForConfigItem = getEngineForConfigItem;
const circom_tester_1 = require("circom_tester");
const crypto_1 = require("crypto");
const os_1 = require("os");
const path_1 = require("path");
const operator_1 = require("../barretenberg/operator");
const index_1 = require("../index");
function encryptData(algorithm, plaintext, key, iv) {
    // chacha20 encrypt
    const cipher = (0, crypto_1.createCipheriv)(algorithm === 'chacha20'
        ? 'chacha20-poly1305'
        : (algorithm === 'aes-256-ctr'
            ? 'aes-256-gcm'
            : 'aes-128-gcm'), key, iv);
    return Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
    ]);
}
function loadCircuit(name) {
    return (0, circom_tester_1.wasm)((0, path_1.join)(__dirname, `../../circuits/tests/${name}.circom`));
}
const fetcher = (0, index_1.makeLocalFileFetch)();
function getEngineForConfigItem(item) {
    return item === 'snarkjs'
        ? 'snarkjs' : (item === 'barretenberg'
        ? 'barretenberg'
        : item === 'gnark'
            ? 'gnark'
            : 'expander');
}
exports.ZK_CONFIG_MAP = {
    'snarkjs': (algorithm) => ((0, index_1.makeSnarkJsZKOperator)({
        algorithm,
        fetcher,
        options: { maxProofConcurrency: 2 }
    })),
    'gnark': (algorithm) => ((0, index_1.makeGnarkZkOperator)({ algorithm, fetcher })),
    'expander-single-thread': (algorithm) => ((0, index_1.makeExpanderZkOperator)({
        algorithm,
        fetcher,
        options: { maxWorkers: 0 }
    })),
    'expander-multi-thread': (algorithm) => ((0, index_1.makeExpanderZkOperator)({
        algorithm,
        fetcher,
        options: { maxWorkers: (0, os_1.cpus)().length }
    })),
    'barretenberg': (algorithm) => ((0, operator_1.makeBarretenbergZKOperator)({
        algorithm,
        fetcher,
        options: { maxProofConcurrency: 2 }
    })),
};
exports.ZK_CONFIGS = Object.keys(exports.ZK_CONFIG_MAP);
