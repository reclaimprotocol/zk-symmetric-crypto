"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeExpanderZkOperator = makeExpanderZkOperator;
const config_1 = require("../config");
const utils_1 = require("../utils");
const node_worker_1 = require("./node-worker");
const utils_2 = require("./utils");
const wasm_binding_1 = require("./wasm-binding");
let wasmInit;
function makeExpanderZkOperator({ algorithm, fetcher, options: { maxWorkers = 0 } = {} }) {
    const { index: id, keySizeBytes } = config_1.CONFIG[algorithm];
    const workerPool = maxWorkers
        ? (0, utils_2.makeWorkerPool)(maxWorkers, _initWorker)
        : undefined;
    let proverLoader;
    let circuitLoader;
    return {
        generateWitness(input) {
            const witness = new Uint8Array([
                // let's just call this the version flag
                1,
                ...(0, utils_1.serialiseValuesToBits)(algorithm, input.counter, input.nonce, input.in, input.out, input.key)
            ]);
            return witness;
        },
        async groth16Prove(witness, logger) {
            const version = readFromWitness(1)[0];
            if (version !== 1) {
                throw new Error(`Unsupported witness version: ${version}`);
            }
            // * 8 because we're reading bits
            const pubBits = readFromWitness(-keySizeBytes * 8);
            const privBits = witness;
            await loadProverAsRequired(logger);
            if (!workerPool) {
                const bytes = (0, wasm_binding_1.prove)(id, privBits, pubBits);
                return { proof: bytes };
            }
            const worker = await workerPool.getNext();
            const { result: proof } = await (worker.rpc('prove', { args: [id, privBits, pubBits] }));
            return { proof };
            function readFromWitness(length) {
                const result = witness.slice(0, length);
                witness = witness.slice(length);
                return result;
            }
        },
        async groth16Verify(publicSignals, proof, logger) {
            if (!(proof instanceof Uint8Array)) {
                throw new Error('Expected proof to be binary');
            }
            await loadCircuitAsRequired(logger);
            const pubSignals = new Uint8Array((0, utils_1.serialiseValuesToBits)(algorithm, publicSignals.counter, publicSignals.nonce, publicSignals.in, publicSignals.out));
            return (0, wasm_binding_1.verify)(id, pubSignals, proof);
        },
        release() {
            return workerPool?.release();
        }
    };
    async function loadProverAsRequired(logger) {
        wasmInit ||= (0, utils_2.loadExpander)(fetcher, logger);
        await wasmInit;
        proverLoader ||= (0, utils_2.loadProverCircuitIfRequired)(algorithm, fetcher, logger);
        circuitLoader ||= (0, utils_2.loadCircuitIfRequired)(algorithm, fetcher, logger);
        await Promise.all([proverLoader, circuitLoader]);
    }
    async function loadCircuitAsRequired(logger) {
        wasmInit ||= (0, utils_2.loadExpander)(fetcher, logger);
        await wasmInit;
        circuitLoader ||= (0, utils_2.loadCircuitIfRequired)(algorithm, fetcher, logger);
        await circuitLoader;
    }
}
async function _initWorker() {
    const { wasm, module } = await wasmInit;
    return (0, node_worker_1.initWorker)({
        module,
        initialisationMemory: new Uint8Array(wasm.memory.buffer),
    });
}
