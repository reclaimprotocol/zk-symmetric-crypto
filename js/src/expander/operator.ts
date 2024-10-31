import { CONFIG } from '../config'
import { Logger, MakeZKOperatorOpts, ZKOperator } from '../types'
import { loadCircuitIfRequired, loadExpander, loadProverCircuitIfRequired } from './utils'
import { prove, verify } from './wasm-binding'

let wasmInit: Promise<void> | undefined

export type ExpanderOpts = {
	maxWorkers?: number
}

export function makeExpanderZkOperator({
	algorithm,
	fetcher
}: MakeZKOperatorOpts<ExpanderOpts>): ZKOperator {
	const { index: id, keySizeBytes } = CONFIG[algorithm]
	let proverLoader: Promise<void> | undefined
	let circuitLoader: Promise<void> | undefined

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
		wasmInit ||= loadExpander(fetcher, logger)
		await wasmInit

		proverLoader ||= loadProverCircuitIfRequired(algorithm, fetcher, logger)
		circuitLoader ||= loadCircuitIfRequired(algorithm, fetcher, logger)
		await Promise.all([proverLoader, circuitLoader])
	}

	async function loadCircuitAsRequired(logger?: Logger) {
		wasmInit ||= loadExpander(fetcher, logger)
		await wasmInit

		circuitLoader ||= loadCircuitIfRequired(algorithm, fetcher, logger)
		await circuitLoader
	}
}