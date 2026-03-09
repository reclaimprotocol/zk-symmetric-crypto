// Benchmark WASM TOPRF operations
import init, {
    bench_toprf_native,
    get_toprf_info,
    get_circuits_info,
    toprf_generate_keys,
    toprf_create_request,
    toprf_evaluate,
    toprf_finalize
} from './pkg/s2circuits.js';
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

    // Test full TOPRF API flow (gnark-compatible)
    console.log("Full TOPRF API Test (gnark-compatible JSON format):");
    console.log("---------------------------------------------------");

    // 1. Generate keys
    console.log("\n1. Generating threshold keys (3-of-2)...");
    const keysJson = toprf_generate_keys(3, 2, BigInt(12345));
    const keys = JSON.parse(keysJson);

    if (keys.error) {
        console.error("Key generation failed:", keys.error);
        return;
    }

    console.log(`   Server public key: ${keys.serverPublicKey.slice(0, 32)}...`);
    console.log(`   Generated ${keys.shares.length} shares`);

    // 2. Create request
    console.log("\n2. Creating OPRF request...");
    const secretBytes = new TextEncoder().encode("test@reclaim.com");
    const requestJson = toprf_create_request(secretBytes, "reclaim");
    const request = JSON.parse(requestJson);

    if (request.error) {
        console.error("Request creation failed:", request.error);
        return;
    }

    console.log(`   Mask: ${request.mask.slice(0, 16)}...`);
    console.log(`   Masked data: ${request.maskedData.slice(0, 32)}...`);

    // 3. Evaluate with shares
    console.log("\n3. Evaluating OPRF with shares 0 and 1...");
    const responses = [];
    for (let i = 0; i < 2; i++) {
        const share = keys.shares[i];
        const responseJson = toprf_evaluate(JSON.stringify(share), request.maskedData);
        const response = JSON.parse(responseJson);

        if (response.error) {
            console.error(`Share ${i} evaluation failed:`, response.error);
            return;
        }

        responses.push(response);
        console.log(`   Share ${i}: evaluated=${response.evaluated.slice(0, 32)}...`);
    }

    // 4. Finalize
    console.log("\n4. Finalizing TOPRF...");
    const finalizeParams = {
        serverPublicKey: keys.serverPublicKey,
        request: request,
        responses: responses
    };

    const resultJson = toprf_finalize(JSON.stringify(finalizeParams));
    const result = JSON.parse(resultJson);

    if (result.error) {
        console.error("Finalization failed:", result.error);
        return;
    }

    console.log(`   Output (hex): ${result.output}`);
    console.log(`   Output (decimal): ${result.outputDecimal}`);
    console.log("\n   Full API test: PASSED");

    // Benchmark native TOPRF verification
    console.log("\n\nNative TOPRF Verification Benchmarks:");
    console.log("--------------------------------------");

    const secrets = [
        "test@reclaim.com",
        "hello@example.org",
        "a_longer_secret_value_for_testing_purposes"
    ];

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
    console.log("- Different hash = different outputs, but same security model");
    console.log("- JSON format is gnark-compatible for interop");
    console.log(`- Estimated constraints: ${toprfInfo.estimated_constraints.toLocaleString()}`);
    console.log(`- Actual constraints: ${toprfInfo.constraints.toLocaleString()}`);
}

main().catch(console.error);
