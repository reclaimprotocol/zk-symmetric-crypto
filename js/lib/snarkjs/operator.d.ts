import { MakeZKOperatorOpts, ZKOperator } from '../types';
type SnarkJSOpts = {
    maxProofConcurrency?: number;
};
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
export declare function makeSnarkJsZKOperator({ algorithm, fetcher, options: { maxProofConcurrency } }: MakeZKOperatorOpts<SnarkJSOpts>): ZKOperator;
export {};
