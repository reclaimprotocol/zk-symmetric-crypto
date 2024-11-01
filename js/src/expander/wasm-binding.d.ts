/* tslint:disable */
/* eslint-disable */
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @param {Uint8Array} bytes
 */
export function load_circuit(alg: SymmetricCryptoAlgorithm, bytes: Uint8Array): void;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @param {Uint8Array} bytes
 */
export function load_solver(alg: SymmetricCryptoAlgorithm, bytes: Uint8Array): void;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @returns {boolean}
 */
export function is_circuit_loaded(alg: SymmetricCryptoAlgorithm): boolean;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @returns {boolean}
 */
export function is_solver_loaded(alg: SymmetricCryptoAlgorithm): boolean;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @param {Uint8Array} priv_input_bits
 * @param {Uint8Array} pub_input_bits
 * @returns {Uint8Array}
 */
export function prove(alg: SymmetricCryptoAlgorithm, priv_input_bits: Uint8Array, pub_input_bits: Uint8Array): Uint8Array;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @param {Uint8Array} pub_input_bits
 * @param {Uint8Array} proof_data
 * @returns {boolean}
 */
export function verify(alg: SymmetricCryptoAlgorithm, pub_input_bits: Uint8Array, proof_data: Uint8Array): boolean;
export enum SymmetricCryptoAlgorithm {
  ChaCha20 = 0,
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly load_circuit: (a: number, b: number, c: number) => void;
  readonly load_solver: (a: number, b: number, c: number) => void;
  readonly is_circuit_loaded: (a: number) => number;
  readonly is_solver_loaded: (a: number) => number;
  readonly prove: (a: number, b: number, c: number, d: number, e: number) => Array;
  readonly verify: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly __wbindgen_export_0: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
