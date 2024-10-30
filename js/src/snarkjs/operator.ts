import { CircuitWasm, Logger, MakeZKOperatorOpts, VerificationKey, ZKOperator } from '../types'

type WitnessData = {
	type: 'mem'
	data?: Uint8Array
}

// 5 pages is enough for the witness data
// calculation
const WITNESS_MEMORY_SIZE_PAGES = 5

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
export function makeSnarkJsZKOperator({
	algorithm,
	fetcher
}: MakeZKOperatorOpts<{}>): ZKOperator {
	// require here to avoid loading snarkjs in
	// any unsupported environments
	const snarkjs = require('snarkjs')
	let zkey: Promise<VerificationKey> | VerificationKey | undefined
	let circuitWasm: Promise<CircuitWasm> | CircuitWasm | undefined
	let wc: Promise<unknown> | undefined

	return {
		// eslint-disable-next-line @typescript-eslint/no-unused-vars
		async generateWitness({ out, ...input }, logger) {
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
			const { data } = await zkey
			return snarkjs.groth16.prove(
				data,
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
				zkeyResult.json,
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

	function getCircuitWasm(logger?: Logger) {
		return fetcher.fetch('snarkjs', `${algorithm}/circuit.wasm`, logger)
	}

	async function getZkey(logger?: Logger) {
		const data = await fetcher
			.fetch('snarkjs', `${algorithm}/circuit_final.zkey`, logger)
		return { data }
	}
}