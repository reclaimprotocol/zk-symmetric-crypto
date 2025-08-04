import type { WorkerChannel, WorkerInitData } from './types';
export declare function initWorker(workerData: WorkerInitData): Promise<WorkerChannel>;
