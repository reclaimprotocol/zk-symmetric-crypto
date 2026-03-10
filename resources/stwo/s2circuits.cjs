/* @ts-self-types="./s2circuits.d.ts" */

/**
 * Benchmark native TOPRF verification (no ZK proof, just the crypto operations).
 *
 * This measures the time for scalar multiplications, hashing, etc.
 * Returns JSON with timing info.
 * @param {Uint8Array} secret_bytes
 * @param {number} domain_separator
 * @returns {string}
 */
function bench_toprf_native(secret_bytes, domain_separator) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passArray8ToWasm0(secret_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.bench_toprf_native(ptr0, len0, domain_separator);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}
exports.bench_toprf_native = bench_toprf_native;

/**
 * Debug: compute ChaCha20 keystream and return it (for debugging WASM issues).
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @returns {string}
 */
function debug_chacha20_keystream(key, nonce, counter) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.debug_chacha20_keystream(ptr0, len0, ptr1, len1, counter);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}
exports.debug_chacha20_keystream = debug_chacha20_keystream;

/**
 * Debug DLEQ verification - returns detailed info about hash computation.
 * @param {string} points_json
 * @returns {string}
 */
function debug_dleq_hash(points_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(points_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.debug_dleq_hash(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}
exports.debug_dleq_hash = debug_dleq_hash;

/**
 * Generate AES-128-CTR proof and return it serialized (base64).
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
function generate_aes128_ctr_proof(key, nonce, counter, plaintext, ciphertext) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.generate_aes128_ctr_proof(ptr0, len0, ptr1, len1, counter, ptr2, len2, ptr3, len3);
        deferred5_0 = ret[0];
        deferred5_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.generate_aes128_ctr_proof = generate_aes128_ctr_proof;

/**
 * Generate AES-256-CTR proof and return it serialized (base64).
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
function generate_aes256_ctr_proof(key, nonce, counter, plaintext, ciphertext) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.generate_aes256_ctr_proof(ptr0, len0, ptr1, len1, counter, ptr2, len2, ptr3, len3);
        deferred5_0 = ret[0];
        deferred5_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.generate_aes256_ctr_proof = generate_aes256_ctr_proof;

/**
 * Generate ChaCha20 proof and return it serialized (base64).
 * Use verify_chacha20_proof() to verify the proof separately.
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
function generate_chacha20_proof(key, nonce, counter, plaintext, ciphertext) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.generate_chacha20_proof(ptr0, len0, ptr1, len1, counter, ptr2, len2, ptr3, len3);
        deferred5_0 = ret[0];
        deferred5_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.generate_chacha20_proof = generate_chacha20_proof;

/**
 * Get circuit information as JSON.
 * @returns {string}
 */
function get_circuits_info() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.get_circuits_info();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
exports.get_circuits_info = get_circuits_info;

/**
 * Get TOPRF circuit info.
 * @returns {string}
 */
function get_toprf_info() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.get_toprf_info();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
exports.get_toprf_info = get_toprf_info;

/**
 * Prove AES-128-CTR encryption.
 *
 * # Arguments
 * * `key` - 16-byte key (Uint8Array) - PRIVATE
 * * `nonce` - 12-byte nonce (Uint8Array) - PUBLIC
 * * `counter` - Starting counter value - PUBLIC
 * * `plaintext` - Plaintext bytes (Uint8Array, must be multiple of 16) - PUBLIC
 * * `ciphertext` - Ciphertext bytes (Uint8Array, same length as plaintext) - PUBLIC
 *
 * # Returns
 * JSON string: {"success": true, "blocks": N} or {"error": "..."}
 *
 * # What the proof demonstrates
 * "I know a secret key K such that AES-128-CTR(K, nonce, counter, plaintext) = ciphertext"
 * The key remains private - the verifier learns nothing about it.
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
function prove_aes128_ctr_encrypt(key, nonce, counter, plaintext, ciphertext) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.prove_aes128_ctr_encrypt(ptr0, len0, ptr1, len1, counter, ptr2, len2, ptr3, len3);
        deferred5_0 = ret[0];
        deferred5_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.prove_aes128_ctr_encrypt = prove_aes128_ctr_encrypt;

/**
 * Prove AES-256-CTR encryption.
 *
 * # Arguments
 * * `key` - 32-byte key (Uint8Array) - PRIVATE
 * * `nonce` - 12-byte nonce (Uint8Array) - PUBLIC
 * * `counter` - Starting counter value - PUBLIC
 * * `plaintext` - Plaintext bytes (Uint8Array, must be multiple of 16) - PUBLIC
 * * `ciphertext` - Ciphertext bytes (Uint8Array, same length as plaintext) - PUBLIC
 *
 * # Returns
 * JSON string: {"success": true, "blocks": N} or {"error": "..."}
 *
 * # What the proof demonstrates
 * "I know a secret key K such that AES-256-CTR(K, nonce, counter, plaintext) = ciphertext"
 * The key remains private - the verifier learns nothing about it.
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
function prove_aes256_ctr_encrypt(key, nonce, counter, plaintext, ciphertext) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.prove_aes256_ctr_encrypt(ptr0, len0, ptr1, len1, counter, ptr2, len2, ptr3, len3);
        deferred5_0 = ret[0];
        deferred5_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.prove_aes256_ctr_encrypt = prove_aes256_ctr_encrypt;

/**
 * Prove ChaCha20 encryption.
 *
 * # Arguments
 * * `key` - 32-byte key (Uint8Array) - PRIVATE
 * * `nonce` - 12-byte nonce (Uint8Array) - PUBLIC
 * * `counter` - Starting counter value - PUBLIC
 * * `plaintext` - Plaintext bytes (Uint8Array, must be multiple of 64) - PUBLIC
 * * `ciphertext` - Ciphertext bytes (Uint8Array, same length as plaintext) - PUBLIC
 *
 * # Returns
 * JSON string: {"success": true, "blocks": N} or {"error": "..."}
 *
 * # What the proof demonstrates
 * "I know a secret key K such that ChaCha20(K, nonce, counter, plaintext) = ciphertext"
 * The key remains private - the verifier learns nothing about it.
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
function prove_chacha20_encrypt(key, nonce, counter, plaintext, ciphertext) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passArray8ToWasm0(key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.prove_chacha20_encrypt(ptr0, len0, ptr1, len1, counter, ptr2, len2, ptr3, len3);
        deferred5_0 = ret[0];
        deferred5_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.prove_chacha20_encrypt = prove_chacha20_encrypt;

/**
 * Create OPRF request (client-side).
 *
 * # Arguments
 * * `secret_bytes` - Secret data to hash (max 62 bytes)
 * * `domain_separator` - Domain separator string
 *
 * # Returns
 * JSON string matching gnark's OPRFRequest format:
 * - mask: hex-encoded scalar
 * - maskedData: hex-encoded 64-byte point
 * - secretElements: [hex, hex] two field elements
 * @param {Uint8Array} secret_bytes
 * @param {string} domain_separator
 * @returns {string}
 */
function toprf_create_request(secret_bytes, domain_separator) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(secret_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(domain_separator, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.toprf_create_request(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}
exports.toprf_create_request = toprf_create_request;

/**
 * Evaluate OPRF (server-side).
 *
 * # Arguments
 * * `share_json` - JSON with share: { index, privateKey, publicKey }
 * * `masked_request_hex` - Hex-encoded 64-byte masked point
 *
 * # Returns
 * JSON string matching gnark's OPRFResponse format:
 * - index: share index
 * - publicKeyShare: hex-encoded 64-byte point
 * - evaluated: hex-encoded 64-byte point
 * - c: hex-encoded DLEQ challenge
 * - r: hex-encoded DLEQ response
 * @param {string} share_json
 * @param {string} masked_request_hex
 * @returns {string}
 */
function toprf_evaluate(share_json, masked_request_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(share_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(masked_request_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.toprf_evaluate(ptr0, len0, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}
exports.toprf_evaluate = toprf_evaluate;

/**
 * Finalize TOPRF (client-side).
 *
 * # Arguments
 * * `params_json` - JSON matching gnark's InputTOPRFFinalizeParams:
 *   - serverPublicKey: hex-encoded 64-byte point
 *   - request: { mask, maskedData, secretElements }
 *   - responses: [{ index, publicKeyShare, evaluated, c, r }, ...]
 *
 * # Returns
 * JSON string with:
 * - output: hex-encoded hash output
 * - outputDecimal: decimal string of output (for comparison)
 * @param {string} params_json
 * @returns {string}
 */
function toprf_finalize(params_json) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(params_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.toprf_finalize(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}
exports.toprf_finalize = toprf_finalize;

/**
 * Generate TOPRF shared keys for threshold scheme.
 *
 * # Arguments
 * * `nodes` - Total number of nodes
 * * `threshold` - Minimum nodes required to reconstruct
 * * `seed` - Random seed for deterministic key generation (for testing)
 *
 * # Returns
 * JSON string with:
 * - serverPublicKey: 64-byte hex-encoded point
 * - shares: Array of share objects with index, privateKey, publicKey
 * @param {number} nodes
 * @param {number} threshold
 * @param {bigint} seed
 * @returns {string}
 */
function toprf_generate_keys(nodes, threshold, seed) {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.toprf_generate_keys(nodes, threshold, seed);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
exports.toprf_generate_keys = toprf_generate_keys;

/**
 * Verify an AES-CTR proof (base64-encoded) against verifier-supplied public inputs.
 * Works for both AES-128 and AES-256.
 *
 * The verifier must provide the expected nonce, counter, plaintext, and ciphertext.
 * Verification fails if the proof was generated for different data.
 * @param {string} proof_b64
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
function verify_aes_ctr_proof(proof_b64, nonce, counter, plaintext, ciphertext) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(proof_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.verify_aes_ctr_proof(ptr0, len0, ptr1, len1, counter, ptr2, len2, ptr3, len3);
        deferred5_0 = ret[0];
        deferred5_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.verify_aes_ctr_proof = verify_aes_ctr_proof;

/**
 * Verify a ChaCha20 proof (base64-encoded) against verifier-supplied public inputs.
 *
 * The verifier must provide the expected nonce, counter, plaintext, and ciphertext.
 * Verification fails if the proof was generated for different data.
 * @param {string} proof_b64
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} ciphertext
 * @returns {string}
 */
function verify_chacha20_proof(proof_b64, nonce, counter, plaintext, ciphertext) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(proof_b64, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(nonce, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.verify_chacha20_proof(ptr0, len0, ptr1, len1, counter, ptr2, len2, ptr3, len3);
        deferred5_0 = ret[0];
        deferred5_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}
exports.verify_chacha20_proof = verify_chacha20_proof;

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_is_function_3c846841762788c1: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_781bc9f159099513: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_7ef6b97b02428fae: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_52709e72fb9f179c: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_6ddd609b62940d55: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_2d781c1f4d5c0ef8: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_instanceof_Window_23e677d2c6843922: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Window;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_length_ea16607d7b61445b: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_with_length_825018a1616e9e55: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_now_c6d7a7d35f74f6f1: function(arg0) {
            const ret = arg0.now();
            return ret;
        },
        __wbg_performance_28be169151161678: function(arg0) {
            const ret = arg0.performance;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_d62e5099504357e6: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_static_accessor_GLOBAL_8adb955bd33fac2f: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_ad356e0db91c7913: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_f207c857566db248: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_bb9f1ba69d61b386: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_a068d24e39478a8a: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./s2circuits_bg.js": import0,
    };
}

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
function decodeText(ptr, len) {
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

const wasmPath = `${__dirname}/s2circuits_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasm = new WebAssembly.Instance(wasmModule, __wbg_get_imports()).exports;
wasm.__wbindgen_start();
