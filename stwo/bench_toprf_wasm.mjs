// Benchmark WASM TOPRF operations
import init, { bench_toprf_native, get_toprf_info, get_circuits_info } from './pkg/s2circuits.js';
import { readFile } from 'fs/promises';

async function main() {
    // Load and initialize WASM
    const wasmBuffer = await readFile('./pkg/s2circuits_bg.wasm');
    await init(wasmBuffer);

    console.log("WASM TOPRF Benchmark");
    console.log("====================\n");

    // Get circuit info
    const circuitInfo = JSON.parse(get_circuits_info());
    console.log("Circuit Info:");
    console.log(JSON.stringify(circuitInfo, null, 2));
    console.log();

    // Get TOPRF-specific info
    const toprfInfo = JSON.parse(get_toprf_info());
    console.log("TOPRF Info:");
    console.log(JSON.stringify(toprfInfo, null, 2));
    console.log();

    // Benchmark native TOPRF verification
    const secrets = [
        "test@reclaim.com",
        "hello@example.org",
        "a]longer]secret]value]for]testing]purposes"
    ];

    console.log("Native TOPRF Verification Benchmarks:");
    console.log("-------------------------------------");

    for (const secret of secrets) {
        const secretBytes = new TextEncoder().encode(secret);
        const domainSeparator = 12345;

        // Warm up
        for (let i = 0; i < 2; i++) {
            bench_toprf_native(secretBytes, domainSeparator);
        }

        // Benchmark
        const iterations = 5;
        const times = [];

        for (let i = 0; i < iterations; i++) {
            const start = performance.now();
            const result = JSON.parse(bench_toprf_native(secretBytes, domainSeparator));
            const elapsed = performance.now() - start;

            if (!result.success) {
                console.error(`Error: ${result.error}`);
                continue;
            }

            times.push(elapsed);
        }

        const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
        const minTime = Math.min(...times);
        const maxTime = Math.max(...times);

        console.log(`\nSecret: "${secret}" (${secret.length} bytes)`);
        console.log(`  Avg: ${avgTime.toFixed(2)}ms`);
        console.log(`  Min: ${minTime.toFixed(2)}ms`);
        console.log(`  Max: ${maxTime.toFixed(2)}ms`);
    }

    console.log("\n\nComparison Notes:");
    console.log("-----------------");
    console.log("- stwo TOPRF uses Poseidon2 over M31 (native field)");
    console.log("- gnark TOPRF uses MiMC over BN254 scalar field");
    console.log("- Different hash = different outputs, but same security");
    console.log(`- Estimated constraints: ${toprfInfo.estimated_constraints.toLocaleString()}`);
    console.log(`- Actual constraints: ${toprfInfo.constraints.toLocaleString()}`);
}

main().catch(console.error);
