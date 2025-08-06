import { EncryptionAlgorithm, FileFetch, Logger } from '../types';
import { WorkerChannel, WorkerPool } from './types';
export declare function loadExpander(fetcher: FileFetch, logger?: Logger): Promise<{
    wasm: import("./wasm-binding").InitOutput;
    module: Uint8Array;
}>;
export declare function loadCircuitIfRequired(alg: EncryptionAlgorithm, fetcher: FileFetch, logger?: Logger): Promise<void>;
export declare function loadProverCircuitIfRequired(alg: EncryptionAlgorithm, fetcher: FileFetch, logger?: Logger): Promise<void>;
export declare function makeWorkerPool(maxWorkers: number, initWorker: () => Promise<WorkerChannel>): WorkerPool;
