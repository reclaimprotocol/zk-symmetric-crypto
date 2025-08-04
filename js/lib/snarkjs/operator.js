"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeSnarkJsZKOperator = makeSnarkJsZKOperator;
const p_queue_1 = __importDefault(require("p-queue"));
const utils_1 = require("../utils");
// 5 pages is enough for the witness data
// calculation
const WITNESS_MEMORY_SIZE_PAGES = 5;
/**
 * Constructs a SnarkJS ZK operator using the provided functions to get
 * the circuit WASM and ZK key. This operator can generate witnesses and
 * produce proofs for zero-knowledge circuits.
 *
 * @param algorithm - operator for the alg: chacha20, aes-256-ctr,
 *  aes-128-ctr
 * @param fetcher - A function that fetches a file by name and returns
 * 	its contents as a Uint8Array.
 *
 * @returns {ZKOperator} A ZK operator that can generate witnesses and
 * 	proofs.
 * @throws {Error} Throws an error if the `snarkjs` library is not available.
 *
 * @example
 * const zkOperator = makeSnarkJsZKOperator({
 *   getCircuitWasm: () => 'path/to/circuit.wasm',
 *   getZkey: () => ({ data: 'path/to/circuit_final.zkey' }),
 * });
 * const witness = await zkOperator.generateWitness(inputData);
 */
function makeSnarkJsZKOperator({ algorithm, fetcher, options: { maxProofConcurrency = 2 } = {} }) {
    let zkey;
    let circuitWasm;
    let wc;
    const snarkjs = loadSnarkjs();
    const concurrencyLimiter = new p_queue_1.default({ concurrency: maxProofConcurrency });
    return {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        async generateWitness({ out, ...input }, logger) {
            circuitWasm ||= getCircuitWasm();
            wc ||= (async () => {
                if (!snarkjs.wtns.getWtnsCalculator) {
                    return;
                }
                // hack to allocate a specific memory size
                // because the Memory size isn't configurable
                // in the circom_runtime package
                const CurMemory = WebAssembly.Memory;
                WebAssembly.Memory = class extends WebAssembly.Memory {
                    constructor() {
                        super({ initial: WITNESS_MEMORY_SIZE_PAGES });
                    }
                };
                try {
                    const rslt = await snarkjs.wtns.getWtnsCalculator(await circuitWasm, logger);
                    return rslt;
                }
                finally {
                    WebAssembly.Memory = CurMemory;
                }
            })();
            const inputBits = {
                key: (0, utils_1.serialiseValuesToBits)(algorithm, input.key),
                nonce: (0, utils_1.serialiseValuesToBits)(algorithm, input.nonce),
                counter: (0, utils_1.serialiseValuesToBits)(algorithm, input.counter),
                in: (0, utils_1.serialiseValuesToBits)(algorithm, input.in),
            };
            const wtns = { type: 'mem' };
            if (await wc) {
                await snarkjs.wtns.wtnsCalculateWithCalculator(inputBits, await wc, wtns);
            }
            else {
                await snarkjs.wtns.calculate(inputBits, await circuitWasm, wtns);
            }
            return wtns.data;
        },
        async groth16Prove(witness, logger) {
            zkey ||= getZkey();
            const { data } = await zkey;
            const { proof } = await concurrencyLimiter.add(() => (snarkjs.groth16.prove(data, witness, logger)));
            return { proof: JSON.stringify(proof) };
        },
        async groth16Verify(publicSignals, proof, logger) {
            proof = typeof proof !== 'string'
                ? Buffer.from(proof).toString()
                : proof;
            zkey ||= getZkey();
            const zkeyResult = await zkey;
            if (!zkeyResult.json) {
                zkeyResult.json = await snarkjs.zKey
                    .exportVerificationKey(zkeyResult.data);
            }
            return snarkjs.groth16.verify(zkeyResult.json, (0, utils_1.serialiseValuesToBits)(algorithm, publicSignals.out, publicSignals.nonce, publicSignals.counter, publicSignals.in), JSON.parse(proof), logger);
        },
        release() {
            zkey = undefined;
            circuitWasm = undefined;
            wc = undefined;
        }
    };
    function getCircuitWasm(logger) {
        return fetcher.fetch('snarkjs', `${algorithm}/circuit.wasm`, logger);
    }
    async function getZkey(logger) {
        const data = await fetcher
            .fetch('snarkjs', `${algorithm}/circuit_final.zkey`, logger);
        return { data };
    }
}
function loadSnarkjs() {
    return require('snarkjs');
}
