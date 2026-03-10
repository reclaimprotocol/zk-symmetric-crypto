/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const prove_chacha20_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
export const prove_aes128_ctr_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
export const prove_aes256_ctr_encrypt: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
export const generate_chacha20_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
export const verify_chacha20_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
export const generate_aes128_ctr_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
export const generate_aes256_ctr_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
export const verify_aes_ctr_proof: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number];
export const debug_chacha20_keystream: (a: number, b: number, c: number, d: number, e: number) => [number, number];
export const get_circuits_info: () => [number, number];
export const bench_toprf_native: (a: number, b: number, c: number) => [number, number];
export const get_toprf_info: () => [number, number];
export const toprf_generate_keys: (a: number, b: number, c: bigint) => [number, number];
export const toprf_create_request: (a: number, b: number, c: number, d: number) => [number, number];
export const toprf_evaluate: (a: number, b: number, c: number, d: number) => [number, number];
export const toprf_finalize: (a: number, b: number) => [number, number];
export const debug_dleq_hash: (a: number, b: number) => [number, number];
export const debug_dleq_verify: (a: number, b: number) => [number, number];
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __wbindgen_start: () => void;
