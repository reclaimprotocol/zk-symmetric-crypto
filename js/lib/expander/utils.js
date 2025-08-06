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
exports.loadExpander = loadExpander;
exports.loadCircuitIfRequired = loadCircuitIfRequired;
exports.loadProverCircuitIfRequired = loadProverCircuitIfRequired;
exports.makeWorkerPool = makeWorkerPool;
const wasm_binding_1 = __importStar(require("./wasm-binding"));
const BIN_NAME = 'release';
async function loadExpander(fetcher, logger) {
    const buff = await fetcher
        .fetch('expander', `${BIN_NAME}.wasm`, logger);
    const wasm = await (0, wasm_binding_1.default)({ 'module_or_path': buff });
    return { wasm, module: buff };
}
async function loadCircuitIfRequired(alg, fetcher, logger) {
    const id = 0;
    if ((0, wasm_binding_1.is_circuit_loaded)(id)) {
        return;
    }
    logger?.debug({ alg }, 'fetching circuit');
    const circuit = await fetcher.fetch('expander', `${alg}.txt`);
    logger?.debug({ alg }, 'circuit fetched, loading...');
    (0, wasm_binding_1.load_circuit)(id, circuit);
    logger?.debug({ alg }, 'circuit loaded');
}
async function loadProverCircuitIfRequired(alg, fetcher, logger) {
    const id = 0;
    if ((0, wasm_binding_1.is_solver_loaded)(id)) {
        return;
    }
    logger?.debug({ alg }, 'fetching solver');
    const circuit = await fetcher.fetch('expander', `${alg}-solver.txt`);
    logger?.debug({ alg }, 'solver fetched, loading...');
    (0, wasm_binding_1.load_solver)(id, circuit);
    logger?.debug({ alg }, 'solver loaded');
}
function makeWorkerPool(maxWorkers, initWorker) {
    let pool = [];
    let nextIdx = 0;
    return {
        getNext() {
            if (pool.length < maxWorkers) {
                pool.push(initWorker());
            }
            const worker = pool[nextIdx];
            nextIdx = (nextIdx + 1) % pool.length;
            return worker;
        },
        async release() {
            const _pool = pool;
            pool = [];
            for (const worker of _pool) {
                const _res = await worker.catch(() => undefined);
                _res?.close();
            }
        },
    };
}
