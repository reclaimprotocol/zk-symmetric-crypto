/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @param {Uint8Array} bytes
 */
export function load_circuit(alg: Readonly<{
    ChaCha20: 0;
    "0": "ChaCha20";
}>, bytes: Uint8Array): void;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @param {Uint8Array} bytes
 */
export function load_solver(alg: Readonly<{
    ChaCha20: 0;
    "0": "ChaCha20";
}>, bytes: Uint8Array): void;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @returns {boolean}
 */
export function is_circuit_loaded(alg: Readonly<{
    ChaCha20: 0;
    "0": "ChaCha20";
}>): boolean;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @returns {boolean}
 */
export function is_solver_loaded(alg: Readonly<{
    ChaCha20: 0;
    "0": "ChaCha20";
}>): boolean;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @param {Uint8Array} priv_input_bits
 * @param {Uint8Array} pub_input_bits
 * @returns {Uint8Array}
 */
export function prove(alg: Readonly<{
    ChaCha20: 0;
    "0": "ChaCha20";
}>, priv_input_bits: Uint8Array, pub_input_bits: Uint8Array): Uint8Array;
/**
 * @param {SymmetricCryptoAlgorithm} alg
 * @param {Uint8Array} pub_input_bits
 * @param {Uint8Array} proof_data
 * @returns {boolean}
 */
export function verify(alg: Readonly<{
    ChaCha20: 0;
    "0": "ChaCha20";
}>, pub_input_bits: Uint8Array, proof_data: Uint8Array): boolean;
export const SymmetricCryptoAlgorithm: Readonly<{
    ChaCha20: 0;
    "0": "ChaCha20";
}>;
export default __wbg_init;
export function initSync(module: any): any;
declare function __wbg_init(module_or_path: any): Promise<any>;
