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
exports.initWorker = initWorker;
const worker_threads_1 = require("worker_threads");
const wasm_binding_js_1 = __importStar(require("./wasm-binding.js"));
const BYTES_PER_PAGE = 65536;
const logger = console;
async function main() {
    const { module, initialisationMemory } = worker_threads_1.workerData;
    const wasm = await (0, wasm_binding_js_1.default)({ 'module_or_path': module });
    const growthRequired = (initialisationMemory.byteLength - wasm.memory.buffer.byteLength) / BYTES_PER_PAGE;
    if (growthRequired > 0) {
        wasm.memory.grow(growthRequired);
        logger.debug({ growthRequired }, 'memory grown');
    }
    // copy initialisation memory
    const memory = new Uint8Array(wasm.memory.buffer);
    memory.set(initialisationMemory);
    logger.debug('worker initialised w memory');
    worker_threads_1.parentPort.on('message', async (msg) => {
        const [type, input] = msg;
        if (type === 'prove') {
            try {
                const result = await (0, wasm_binding_js_1.prove)(...input.args);
                sendOutputRpcBack({ id: input.id, result });
                logger.debug({ id: input.id }, 'prove done');
            }
            catch (err) {
                logger.error({ err }, 'prove error');
                sendOutputRpcBack({
                    id: input.id,
                    type: 'error',
                    message: err.message,
                    stack: err.stack
                });
            }
            return;
        }
        throw new Error(`Unknown message type: ${type}`);
    });
    worker_threads_1.parentPort.postMessage({ type: 'online' });
    function sendOutputRpcBack(output) {
        worker_threads_1.parentPort.postMessage(['reply', output]);
    }
}
async function initWorker(workerData) {
    const worker = new worker_threads_1.Worker(__filename, { workerData });
    await new Promise((resolve, reject) => {
        worker.once('message', resolve);
        worker.once('error', reject);
    });
    const channel = {
        rpc(type, input) {
            input.id ||= createRpcId();
            const wait = waitForRpcReply(input.id);
            worker.postMessage([type, input]);
            return wait;
        },
        close() {
            return worker.terminate();
        }
    };
    return channel;
    async function waitForRpcReply(id) {
        return new Promise((resolve, reject) => {
            worker.on('message', listener);
            worker.once('error', reject);
            async function listener([type, output]) {
                if (type !== 'reply' || output.id !== id) {
                    return;
                }
                worker.off('message', listener);
                worker.off('error', reject);
                if ('type' in output && output.type === 'error') {
                    const err = new Error(output.message);
                    err.stack = output.stack;
                    reject(err);
                    return;
                }
                resolve(output);
            }
        });
    }
}
function createRpcId() {
    return Math.random().toString(36).slice(2);
}
if (!worker_threads_1.isMainThread) {
    main();
}
