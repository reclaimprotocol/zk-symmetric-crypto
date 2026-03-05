// Benchmark WASM ChaCha bitwise prover
import init, { prove_chacha_bitwise } from './pkg/s2circuits.js';
import { readFile } from 'fs/promises';

async function main() {
    // Load and initialize WASM
    const wasmBuffer = await readFile('./pkg/s2circuits_bg.wasm');
    await init(wasmBuffer);

    console.log("WASM Bitwise ChaCha Benchmark");
    console.log("==============================\n");

    // Note: log_size must be >= 4 (LOG_N_LANES) for SIMD
    for (const log_size of [4, 5, 6]) {
        const n_blocks = 1 << log_size;
        const keystream_bytes = n_blocks * 64;

        console.log(`log_size=${log_size}: ${n_blocks} blocks (${keystream_bytes} bytes)`);

        const start = performance.now();
        const result = prove_chacha_bitwise(log_size);
        const elapsed = performance.now() - start;

        console.log(`  Time: ${elapsed.toFixed(2)}ms`);
        console.log(`  Result: ${result}`);
        console.log(`  Throughput: ${(keystream_bytes / (elapsed / 1000) / 1024).toFixed(2)} KB/s`);
        console.log();
    }
}

main().catch(console.error);
