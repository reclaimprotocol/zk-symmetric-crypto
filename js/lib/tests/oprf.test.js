"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = require("../config");
const file_fetch_1 = require("../file-fetch");
const toprf_1 = require("../gnark/toprf");
const utils_1 = require("../gnark/utils");
const zk_1 = require("../zk");
const utils_2 = require("./utils");
jest.setTimeout(10_000);
const fetcher = (0, file_fetch_1.makeLocalFileFetch)();
const threshold = 1;
const POSITIONS = [
    0,
    10
];
const OPRF_ZK_ENGINES_MAP = {
    'gnark': {
        make: algorithm => (0, toprf_1.makeGnarkOPRFOperator)({ fetcher, algorithm }),
        algorithms: ['chacha20', 'aes-128-ctr', 'aes-256-ctr'],
    }
};
const OPRF_ENGINES = Object.keys(OPRF_ZK_ENGINES_MAP);
describe.each(OPRF_ENGINES)('%s TOPRF circuits Tests', engine => {
    const { make, algorithms } = OPRF_ZK_ENGINES_MAP[engine];
    describe.each(algorithms)('%s', algorithm => {
        const operator = make(algorithm);
        it.each(POSITIONS)('should prove & verify TOPRF at pos=%s', async (pos) => {
            const email = 'test@email.com';
            const domainSeparator = 'reclaim';
            const keys = await operator.generateThresholdKeys(5, threshold);
            const req = await operator
                .generateOPRFRequestData((0, utils_1.strToUint8Array)(email), domainSeparator);
            const resps = [];
            for (let i = 0; i < threshold; i++) {
                const evalResult = await operator.evaluateOPRF(keys.shares[i].privateKey, req.maskedData);
                resps.push({
                    publicKeyShare: keys.shares[i].publicKey,
                    evaluated: evalResult.evaluated,
                    c: evalResult.c,
                    r: evalResult.r,
                });
            }
            const nullifier = await operator
                .finaliseOPRF(keys.publicKey, req, resps);
            const len = email.length;
            const plaintext = new Uint8Array(Buffer.alloc(64));
            //replace part of plaintext with email
            plaintext.set(new Uint8Array(Buffer.from(email)), pos);
            const { keySizeBytes } = config_1.CONFIG[algorithm];
            const key = new Uint8Array(Array.from(Array(keySizeBytes).keys()));
            const iv = new Uint8Array(Array.from(Array(12).keys()));
            const ciphertext = (0, utils_2.encryptData)(algorithm, plaintext, key, iv);
            const toprf = {
                pos: pos, //pos in plaintext
                len: len, // length of data to "hash"
                domainSeparator,
                output: nullifier,
                responses: resps
            };
            const proof = await (0, zk_1.generateProof)({
                algorithm,
                privateInput: {
                    key,
                },
                publicInput: { iv, ciphertext },
                operator,
                mask: req.mask,
                toprf,
            });
            await expect((0, zk_1.verifyProof)({
                proof,
                publicInput: { iv, ciphertext },
                toprf,
                operator
            })).resolves.toBeUndefined();
        });
    });
});
