import type { prove } from './wasm-binding';
export type WorkerInitData = {
    module: Uint8Array;
    initialisationMemory: Uint8Array;
};
export type WorkerPool = {
    getNext(): Promise<WorkerChannel>;
    release(): Promise<void>;
};
export type ErrorRPCMessage = {
    id: string;
    type: 'error';
    message: string;
    stack?: string;
};
export type RPCMessageMap = {
    'prove': {
        input: {
            id?: string;
            args: Parameters<typeof prove>;
        };
        output: {
            id: string;
            result: Uint8Array;
        };
    };
};
export type WorkerChannel = {
    rpc<R extends keyof RPCMessageMap>(type: R, payload: RPCMessageMap[R]['input']): Promise<RPCMessageMap[R]['output']>;
    close(): void;
};
