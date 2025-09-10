"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.makeBarretenbergZKOperator = makeBarretenbergZKOperator;
const bb_js_1 = require("@aztec/bb.js");
// @ts-ignore
const noir_js_1 = require("@noir-lang/noir_js");
const utils_1 = require("./utils");
/**
 * Creates a Barretenberg ZK operator for Noir circuits
 * This operator uses the UltraHonk proving system from Barretenberg
 */
function makeBarretenbergZKOperator({ algorithm, fetcher, options: { threads = 1 } = {} }) {
    let circuit;
    let noir;
    let backend;
    async function loadCircuit(logger) {
        if (!circuit) {
            logger?.info?.(`Loading Noir circuit for ${algorithm}`);
            const circuitData = await fetcher.fetch('barretenberg', (0, utils_1.getCircuitFilename)(algorithm), logger);
            circuit = JSON.parse(new TextDecoder().decode(circuitData));
            logger?.info?.('Circuit loaded successfully');
        }
        return circuit;
    }
    async function initializeBackend(logger) {
        if (!noir || !backend) {
            const loadedCircuit = await loadCircuit(logger);
            noir = new noir_js_1.Noir(loadedCircuit);
            backend = new bb_js_1.UltraHonkBackend(loadedCircuit.bytecode, { threads });
            logger?.info?.(`Barretenberg backend initialized with ${threads} threads`);
        }
        return { noir, backend };
    }
    return {
        async generateWitness(input, logger) {
            const { noir: noirInstance } = await initializeBackend(logger);
            // Convert input to Noir witness format
            const noirInput = (0, utils_1.convertToNoirWitness)(algorithm, input);
            // console.log('noirInput', JSON.stringify(noirInput, null, 2))
            logger?.debug?.('Executing Noir circuit...');
            const { witness } = await noirInstance.execute(noirInput);
            // console.log('witness length', witness.length)
            logger?.debug?.('Witness generated successfully');
            return witness;
        },
        async ultrahonkProve(witness, logger) {
            const { backend: backendInstance } = await initializeBackend(logger);
            logger?.info?.('Generating proof with UltraHonk backend...');
            const startTime = Date.now();
            const proofData = await backendInstance.generateProof(witness);
            const proofTime = Date.now() - startTime;
            logger?.info?.(`Proof generated in ${proofTime}ms, size: ${proofData.proof.length} bytes`);
            // Store the full proof data (including public inputs) in the proof bytes
            // We'll need to reconstruct this for verification
            const fullProof = {
                proof: Array.from(proofData.proof),
                publicInputs: proofData.publicInputs
            };
            const proofBytes = new TextEncoder().encode(JSON.stringify(fullProof));
            return { proof: proofBytes };
        },
        async ultrahonkVerify(publicSignals, proof, logger) {
            const { backend: backendInstance } = await initializeBackend(logger);
            logger?.info?.('Verifying proof with UltraHonk backend...');
            const startTime = Date.now();
            try {
                // Parse the proof data from the encoded bytes
                const proofBytes = typeof proof === 'string'
                    ? new Uint8Array(Buffer.from(proof, 'hex'))
                    : proof;
                const fullProof = JSON.parse(new TextDecoder().decode(proofBytes));
                const proofData = {
                    proof: new Uint8Array(fullProof.proof),
                    publicInputs: fullProof.publicInputs
                };
                const isValid = await backendInstance.verifyProof(proofData);
                const verifyTime = Date.now() - startTime;
                logger?.info?.(`Proof verification completed in ${verifyTime}ms, result: ${isValid}`);
                return isValid;
            }
            catch (error) {
                logger?.error?.(`Proof verification failed: ${error}`);
                // console.error('Verification error details:', error)
                return false;
            }
        }
    };
}
