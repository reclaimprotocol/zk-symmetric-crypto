import { CONFIG } from '../config'
import { Logger, MakeZKOperatorOpts, ZKOperator } from '../types'
import { loadCircuitIfRequired, loadExpander, loadProverCircuitIfRequired } from './utils'
import { prove, verify } from './wasm-binding'

let wasmInitDone = false

export function makeExpanderZkOperator({
	algorithm,
	fetcher
}: MakeZKOperatorOpts<{}>): ZKOperator {
	const { index: id, keySizeBytes } = CONFIG[algorithm]
	let loadedProver = false
	let loadedCircuit = false
	return {
		generateWitness(input) {
			const witness = new Uint8Array([
				// let's just call this the version flag
				1,
				...input.counter,
				...input.nonce,
				...input.in,
				...input.out,
				...input.key
			])
			return witness
		},
		async groth16Prove(witness, logger) {
			const version = readFromWitness(1)[0]
			if(version !== 1) {
				throw new Error(`Unsupported witness version: ${version}`)
			}

			const pubBits = readFromWitness(-keySizeBytes * 8)
			const privBits = witness

			await loadProverAsRequired(logger)

			const bytes = prove(id, privBits, pubBits)
			return { proof: bytes }

			function readFromWitness(length: number) {
				const result = witness.slice(0, length)
				witness = witness.slice(length)
				return result
			}
		},
		async groth16Verify(publicSignals, proof, logger) {
			if(!(proof instanceof Uint8Array)) {
				throw new Error('Expected proof to be binary')
			}

			await loadCircuitAsRequired(logger)

			const pubSignals = new Uint8Array([
				...publicSignals.counter,
				...publicSignals.nonce,
				...publicSignals.in,
				...publicSignals.out,
			])

			return verify(id, pubSignals, proof)
		},
	}

	async function loadProverAsRequired(logger?: Logger) {
		if(!wasmInitDone) {
			await loadExpander(fetcher, logger)
			wasmInitDone = true
		}

		if(loadedProver) {
			return
		}

		await Promise.all([
			loadProverCircuitIfRequired(algorithm, fetcher, logger),
			loadCircuitIfRequired(algorithm, fetcher, logger)
		])
		loadedCircuit = true
		loadedProver = true
	}

	async function loadCircuitAsRequired(logger?: Logger) {
		if(!wasmInitDone) {
			await loadExpander(fetcher, logger)
			wasmInitDone = true
		}

		if(loadedCircuit) {
			return
		}

		await loadCircuitIfRequired(algorithm, fetcher, logger)
		loadedCircuit = true
	}
}