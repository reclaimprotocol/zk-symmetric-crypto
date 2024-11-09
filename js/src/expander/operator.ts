import { CONFIG } from '../config'
import { Logger, MakeZKOperatorOpts, ZKOperator } from '../types'
import { serialiseValuesToBits } from '../utils'
import { initWorker } from './node-worker'
import { loadCircuitIfRequired, loadExpander, loadProverCircuitIfRequired, makeWorkerPool } from './utils'
import { prove, verify } from './wasm-binding'

let wasmInit: ReturnType<typeof loadExpander> | undefined

export type ExpanderOpts = {
	/**
	 * Number of parallel workers to use.
	 * Set to 0 to disable parallelism.
	 * @default 0
	 */
	maxWorkers?: number
}

export function makeExpanderZkOperator({
	algorithm,
	fetcher,
	options: { maxWorkers = 0 } = {}
}: MakeZKOperatorOpts<ExpanderOpts>): ZKOperator {
	const { index: id, keySizeBytes } = CONFIG[algorithm]
	const workerPool = maxWorkers
		? makeWorkerPool(maxWorkers, _initWorker)
		: undefined

	let proverLoader: Promise<void> | undefined
	let circuitLoader: Promise<void> | undefined

	return {
		generateWitness(input) {
			const witness = new Uint8Array([
				// let's just call this the version flag
				1,
				...serialiseValuesToBits(
					algorithm,
					input.counter,
					input.nonce,
					input.in,
					input.out,
					input.key
				)
			])
			return witness
		},
		async groth16Prove(witness, logger) {
			const version = readFromWitness(1)[0]
			if(version !== 1) {
				throw new Error(`Unsupported witness version: ${version}`)
			}

			// * 8 because we're reading bits
			const pubBits = readFromWitness(-keySizeBytes * 8)
			const privBits = witness

			await loadProverAsRequired(logger)
			if(!workerPool) {
				const bytes = prove(id, privBits, pubBits)
				return { proof: bytes }
			}

			const worker = await workerPool.getNext()
			const { result: proof } = await (
				worker.rpc('prove', { args: [id, privBits, pubBits] })
			)

			return { proof }

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

			const pubSignals = new Uint8Array(
				serialiseValuesToBits(
					algorithm,
					publicSignals.counter,
					publicSignals.nonce,
					publicSignals.in,
					publicSignals.out,
				)
			)

			return verify(id, pubSignals, proof)
		},
		release() {
			return workerPool?.release()
		}
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

async function _initWorker() {
	const { wasm, module } = await wasmInit!

	return initWorker({
		module,
		initialisationMemory: new Uint8Array(wasm.memory.buffer),
	})
}