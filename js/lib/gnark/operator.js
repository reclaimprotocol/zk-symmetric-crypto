"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeGnarkZkOperator = makeGnarkZkOperator;
const js_base64_1 = require("js-base64");
const config_1 = require("../config");
const utils_1 = require("../utils");
const utils_2 = require("./utils");
const ALGS_MAP = {
    'chacha20': { ext: 'chacha20' },
    'aes-128-ctr': { ext: 'aes128' },
    'aes-256-ctr': { ext: 'aes256' },
};
function makeGnarkZkOperator({ algorithm, fetcher }) {
    return {
        async generateWitness(input) {
            return (0, utils_2.serialiseGnarkWitness)(algorithm, input);
        },
        async groth16Prove(witness, logger) {
            const lib = await initGnark(logger);
            const { proof, publicSignals } = await (0, utils_2.executeGnarkFnAndGetJson)(lib.prove, witness);
            return {
                proof: js_base64_1.Base64.toUint8Array(proof),
                publicSignals: Array.from(js_base64_1.Base64.toUint8Array(publicSignals))
            };
        },
        async groth16Verify(publicSignals, proof, logger) {
            const lib = await initGnark(logger);
            const pubSignals = js_base64_1.Base64.fromUint8Array(new Uint8Array([
                ...publicSignals.out,
                ...publicSignals.nonce,
                ...(0, utils_1.serialiseNumberTo4Bytes)(algorithm, publicSignals.counter),
                ...publicSignals.in
            ]));
            const verifyParams = JSON.stringify({
                cipher: algorithm,
                proof: typeof proof === 'string'
                    ? proof
                    : js_base64_1.Base64.fromUint8Array(proof),
                publicSignals: pubSignals,
            });
            return (0, utils_2.executeGnarkFn)(lib.verify, verifyParams) === 1;
        },
    };
    async function initGnark(logger) {
        const { ext } = ALGS_MAP[algorithm];
        const { index: id } = config_1.CONFIG[algorithm];
        return (0, utils_2.initGnarkAlgorithm)(id, ext, fetcher, logger);
    }
}
