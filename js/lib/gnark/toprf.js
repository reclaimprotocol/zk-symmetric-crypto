"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeGnarkOPRFOperator = makeGnarkOPRFOperator;
const js_base64_1 = require("js-base64");
const koffi = __importStar(require("koffi"));
const utils_1 = require("./utils");
const ALGS_MAP = {
    'chacha20': { ext: 'chacha20_oprf', id: 3 },
    'aes-128-ctr': { ext: 'aes128_oprf', id: 4 },
    'aes-256-ctr': { ext: 'aes256_oprf', id: 5 },
};
function makeGnarkOPRFOperator({ fetcher, algorithm }) {
    return {
        async generateWitness(input) {
            return (0, utils_1.serialiseGnarkWitness)(algorithm, input);
        },
        async groth16Prove(witness, logger) {
            const lib = await initGnark(logger);
            const { proof } = await (0, utils_1.executeGnarkFnAndGetJson)(lib.prove, witness);
            return { proof: js_base64_1.Base64.toUint8Array(proof) };
        },
        async groth16Verify(publicSignals, proof, logger) {
            const lib = await initGnark(logger);
            const pubSignals = (0, utils_1.serialiseGnarkWitness)(algorithm, publicSignals);
            const verifyParams = JSON.stringify({
                cipher: `${algorithm}-toprf`,
                proof: typeof proof === 'string'
                    ? proof
                    : js_base64_1.Base64.fromUint8Array(proof),
                publicSignals: js_base64_1.Base64.fromUint8Array(pubSignals),
            });
            return (0, utils_1.executeGnarkFn)(lib.verify, verifyParams) === 1;
        },
        async generateThresholdKeys(total, threshold, logger) {
            const lib = await initGnark(logger);
            const { generateThresholdKeys, vfree } = lib;
            const params = { total: total, threshold: threshold };
            const res = (0, utils_1.executeGnarkFn)(generateThresholdKeys, JSON.stringify(params));
            const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString();
            vfree(res.r0); // Avoid memory leak!
            const parsed = JSON.parse(resJson);
            const shares = [];
            for (let i = 0; i < parsed.shares.length; i++) {
                const share = parsed.shares[i];
                shares.push({
                    index: share.index,
                    publicKey: (0, js_base64_1.toUint8Array)(share.publicKey),
                    privateKey: (0, js_base64_1.toUint8Array)(share.privateKey),
                });
            }
            return {
                publicKey: (0, js_base64_1.toUint8Array)(parsed.publicKey),
                privateKey: (0, js_base64_1.toUint8Array)(parsed.privateKey),
                shares: shares,
            };
        },
        async generateOPRFRequestData(data, domainSeparator, logger) {
            const lib = await initGnark(logger);
            const params = {
                data: js_base64_1.Base64.fromUint8Array(data),
                domainSeparator: domainSeparator,
            };
            const parsed = await (0, utils_1.executeGnarkFnAndGetJson)(lib.generateOPRFRequest, JSON.stringify(params));
            return {
                mask: (0, js_base64_1.toUint8Array)(parsed.mask),
                maskedData: (0, js_base64_1.toUint8Array)(parsed.maskedData),
                secretElements: [
                    (0, js_base64_1.toUint8Array)(parsed.secretElements[0]),
                    (0, js_base64_1.toUint8Array)(parsed.secretElements[1])
                ]
            };
        },
        async finaliseOPRF(serverPublicKey, request, responses, logger) {
            const lib = await initGnark(logger);
            const params = {
                serverPublicKey: (0, js_base64_1.fromUint8Array)(serverPublicKey),
                request: {
                    mask: (0, js_base64_1.fromUint8Array)(request.mask),
                    maskedData: (0, js_base64_1.fromUint8Array)(request.maskedData),
                    secretElements: [
                        (0, js_base64_1.fromUint8Array)(request.secretElements[0]),
                        (0, js_base64_1.fromUint8Array)(request.secretElements[1])
                    ]
                },
                responses: responses.map(({ publicKeyShare, evaluated, c, r }) => ({
                    publicKeyShare: (0, js_base64_1.fromUint8Array)(publicKeyShare),
                    evaluated: (0, js_base64_1.fromUint8Array)(evaluated),
                    c: (0, js_base64_1.fromUint8Array)(c),
                    r: (0, js_base64_1.fromUint8Array)(r),
                }))
            };
            const parsed = await (0, utils_1.executeGnarkFnAndGetJson)(lib.toprfFinalize, JSON.stringify(params));
            return (0, js_base64_1.toUint8Array)(parsed.output);
        },
        async evaluateOPRF(serverPrivate, maskedData, logger) {
            const lib = await initGnark(logger);
            const { oprfEvaluate, vfree } = lib;
            const params = {
                serverPrivate: (0, js_base64_1.fromUint8Array)(serverPrivate),
                maskedData: (0, js_base64_1.fromUint8Array)(maskedData),
            };
            const res = (0, utils_1.executeGnarkFn)(oprfEvaluate, JSON.stringify(params));
            const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString();
            vfree(res.r0); // Avoid memory leak!
            const parsed = JSON.parse(resJson);
            return {
                evaluated: (0, js_base64_1.toUint8Array)(parsed.evaluated),
                c: (0, js_base64_1.toUint8Array)(parsed.c),
                r: (0, js_base64_1.toUint8Array)(parsed.r),
            };
        },
    };
    async function initGnark(logger) {
        const { ext, id } = ALGS_MAP[algorithm];
        return (0, utils_1.initGnarkAlgorithm)(id, ext, fetcher, logger);
    }
}
