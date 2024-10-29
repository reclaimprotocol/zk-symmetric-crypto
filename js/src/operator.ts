import { CircuitWasm, EncryptionAlgorithm, VerificationKey, ZKOperator, ZKParams } from "./types";

type WitnessData = {
	type: 'mem'
	data?: Uint8Array
}

// 5 pages is enough for the witness data
// calculation
const WITNESS_MEMORY_SIZE_PAGES = 5

/**
 * Creates a local SnarkJS ZK operator for a given encryption algorithm.
 *
 * This function dynamically imports the `snarkjs` library and constructs a 
 * ZK operator that can generate witnesses,build and verify proofs based on the specified 
 * encryption algorithm type.
 *
 * @param {EncryptionAlgorithm} type - The encryption algorithm to be used.('chacha20','aes-256-ctr','aes-128-ctr')
 * @returns {Promise<ZKOperator>} A promise that resolves to a ZK operator.(interanlly calls `makeSnarkJsZKOperator`)
 * @throws {Error} Throws an error if the specified algorithm type is not supported.
 *
 * @example
 * const zkOperator = await makeLocalSnarkJsZkOperator('chacha20');
 * const witness = await zkOperator.generateWitness(inputData);
 */
export async function makeLocalSnarkJsZkOperator(
	type: EncryptionAlgorithm,
) {
	const { join } = await import('path')
	const folder = `../../resources/circom/${type}`
	return makeSnarkJsZKOperator(
		{
			getZkey: () => ({
				data: join(
					__dirname,
					`${folder}/circuit_final.zkey`
				)
			}),
			getCircuitWasm: () => join(
				__dirname,
				`${folder}/circuit.wasm`
			),
		},
	)
}

/**
 * Constructs a SnarkJS ZK operator using the provided functions to get 
 * the circuit WASM and ZK key. This operator can generate witnesses and 
 * produce proofs for zero-knowledge circuits.
 *
 * @param {getCircuitWasm,getZkey} ZKParams - An object containing functions to retrieve the circuit WASM from path.
 * 
 * @returns {ZKOperator} A ZK operator that can generate witnesses and proofs.
 * @throws {Error} Throws an error if the `snarkjs` library is not available.
 *
 * @example
 * const zkOperator = makeSnarkJsZKOperator({
 *   getCircuitWasm: () => 'path/to/circuit.wasm',
 *   getZkey: () => ({ data: 'path/to/circuit_final.zkey' }),
 * });
 * const witness = await zkOperator.generateWitness(inputData);
 */
export function makeSnarkJsZKOperator(
	{ getCircuitWasm, getZkey }: ZKParams,
): ZKOperator {
	// require here to avoid loading snarkjs in
	// any unsupported environments
	const snarkjs = require('snarkjs')
	let zkey: Promise<VerificationKey> | VerificationKey | undefined
	let circuitWasm: Promise<CircuitWasm> | CircuitWasm | undefined
	let wc: Promise<any> | undefined

	return {
		async generateWitness(input, logger) {
			circuitWasm ||= getCircuitWasm()
			wc ||= (async() => {
				if(!snarkjs.wtns.getWtnsCalculator) {
					return
				}

				// hack to allocate a specific memory size
				// because the Memory size isn't configurable
				// in the circom_runtime package
				const CurMemory = WebAssembly.Memory
				WebAssembly.Memory = class extends WebAssembly.Memory {
					constructor() {
						super({ initial: WITNESS_MEMORY_SIZE_PAGES })
					}
				}

				try {
					const rslt = await snarkjs.wtns.getWtnsCalculator(
						await circuitWasm,
						logger
					)

					return rslt
				} finally {
					WebAssembly.Memory = CurMemory
				}
			})()

			const wtns: WitnessData = { type: 'mem' }
			if(await wc) {
				await snarkjs.wtns.wtnsCalculateWithCalculator(
					input,
					await wc,
					wtns,
				)
			} else {
				await snarkjs.wtns.calculate(
					input,
					await circuitWasm,
					wtns,
				)
			}
			
			return wtns.data!
		},
		async groth16Prove(witness, logger) {
			zkey ||= getZkey()
			return snarkjs.groth16.prove(
				(await zkey).data,
				witness,
				logger
			)
		},
		async groth16Verify(publicSignals, proof, logger) {
			zkey ||= getZkey()
			const zkeyResult = await zkey
			if(!zkeyResult.json) {
				zkeyResult.json = await snarkjs.zKey
					.exportVerificationKey(zkeyResult.data)
			}

			return snarkjs.groth16.verify(
				zkeyResult.json!,
				publicSignals,
				proof,
				logger
			)
		},
		release() {
			zkey = undefined
			circuitWasm = undefined
			wc = undefined
		}
	}
}