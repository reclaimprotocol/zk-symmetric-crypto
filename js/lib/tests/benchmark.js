"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
const tinybench_1 = require("tinybench");
const config_1 = require("../config");
const types_1 = require("../types");
const zk_1 = require("../zk");
const utils_1 = require("./utils");
const ALL_ALGOS = [
    'chacha20',
    //'aes-256-ctr',
    //'aes-128-ctr',
];
const DATA_LENGTH = 1024;
const BENCHES = ALL_ALGOS.map((algo) => {
    let bench = new tinybench_1.Bench({
        name: `Generate Proof - ${algo}`,
        iterations: 1,
    });
    for (const engine of utils_1.ZK_CONFIGS) {
        const operator = utils_1.ZK_CONFIG_MAP[engine](algo);
        let witnesses;
        bench = bench.add(engine, async () => {
            try {
                const now = Date.now();
                await Promise.all(witnesses.map((witness) => {
                    if ((0, types_1.isBarretenbergOperator)(operator)) {
                        return operator.ultrahonkProve(witness);
                    }
                    else {
                        return operator.groth16Prove(witness);
                    }
                }));
                const elapsed = Date.now() - now;
                console.log(`Generated ${witnesses.length} proofs for ${algo} using ${engine}, ${elapsed}ms`);
            }
            catch (err) {
                console.error(err);
            }
        }, {
            beforeEach: async () => {
                witnesses = await prepareDataForAlgo(algo, operator);
                console.log(`Prepared ${witnesses.length} witnesses for ${algo} using ${engine}`);
            },
        });
    }
    return bench;
});
async function main() {
    for (const bench of BENCHES) {
        await bench.run();
        console.log(bench.name);
        console.table(bench.table());
    }
}
async function prepareDataForAlgo(algo, operator) {
    const { keySizeBytes, chunkSize, bitsPerWord } = config_1.CONFIG[algo];
    const plaintext = new Uint8Array((0, crypto_1.randomBytes)(DATA_LENGTH));
    const privateInput = {
        key: Buffer.alloc(keySizeBytes, 2),
    };
    const iv = new Uint8Array(12).fill(0);
    const ciphertext = (0, utils_1.encryptData)(algo, plaintext, privateInput.key, iv);
    const witnesses = [];
    const chunkSizeBytes = chunkSize * bitsPerWord / 8;
    for (let i = 0; i < ciphertext.length; i += chunkSizeBytes) {
        const publicInput = {
            ciphertext: ciphertext.subarray(i, i + chunkSizeBytes),
            iv: iv,
            offsetBytes: i
        };
        const { witness } = await (0, zk_1.generateZkWitness)({
            algorithm: algo,
            privateInput,
            publicInput
        });
        const wtnsSerialised = await operator.generateWitness(witness);
        witnesses.push(wtnsSerialised);
    }
    return witnesses;
}
main();
