import { EncryptionAlgorithm, FileFetch, Logger, ZKProofInput, ZKProofInputOPRF, ZKProofPublicSignals, ZKProofPublicSignalsOPRF } from '../types';
export type GnarkLib = {
    verify: Function;
    free: Function;
    vfree: Function;
    prove: Function;
    initAlgorithm: Function;
    generateThresholdKeys: Function;
    oprfEvaluate: Function;
    generateOPRFRequest: Function;
    toprfFinalize: Function;
    koffi: typeof import('koffi');
};
export declare function initGnarkAlgorithm(id: number, fileExt: string, fetcher: FileFetch, logger?: Logger): Promise<GnarkLib>;
export declare function strToUint8Array(str: string): Uint8Array;
export declare function serialiseGnarkWitness(cipher: EncryptionAlgorithm, input: ZKProofInput | ZKProofInputOPRF | ZKProofPublicSignals | ZKProofPublicSignalsOPRF): Uint8Array;
export declare function generateGnarkWitness(cipher: EncryptionAlgorithm, input: ZKProofInput | ZKProofInputOPRF | ZKProofPublicSignals | ZKProofPublicSignalsOPRF): {
    cipher: string;
    key: string | undefined;
    nonce: string;
    counter: number;
    input: string;
    toprf: {
        pos?: undefined;
        len?: undefined;
        domainSeparator?: undefined;
        output?: undefined;
        responses?: undefined;
        mask?: undefined;
    } | {
        pos: number;
        len: number;
        domainSeparator: string;
        output: string;
        responses: {
            publicKeyShare: string;
            evaluated: string;
            c: string;
            r: string;
        }[];
        mask: string;
    };
};
export declare function executeGnarkFn(fn: Function, jsonInput: string | Uint8Array): any;
export declare function executeGnarkFnAndGetJson(fn: Function, jsonInput: string | Uint8Array): Promise<any>;
