import { EncryptionAlgorithm, FileFetch, Logger } from '../types'
import { WorkerChannel, WorkerPool } from './types'
import init, { is_circuit_loaded, is_solver_loaded, load_circuit, load_solver } from './wasm-binding'

const BIN_NAME = 'release'

export async function loadExpander(
	fetcher: FileFetch,
	logger?: Logger
) {
	const buff = await fetcher
		.fetch('expander', `${BIN_NAME}.wasm`, logger)
	const wasm = await init({ 'module_or_path': buff })
	return { wasm, module: buff }
}

export async function loadCircuitIfRequired(
	alg: EncryptionAlgorithm,
	fetcher: FileFetch,
	logger?: Logger
) {
	const id = 0
	if(is_circuit_loaded(id)) {
		return
	}

	logger?.debug({ alg }, 'fetching circuit')

	const circuit = await fetcher.fetch(
		'expander',
		`${alg}.txt`
	)

	logger?.debug({ alg }, 'circuit fetched, loading...')

	load_circuit(id, circuit)

	logger?.debug({ alg }, 'circuit loaded')
}

export async function loadProverCircuitIfRequired(
	alg: EncryptionAlgorithm,
	fetcher: FileFetch,
	logger?: Logger
) {
	const id = 0
	if(is_solver_loaded(id)) {
		return
	}

	logger?.debug({ alg }, 'fetching solver')

	const circuit = await fetcher.fetch(
		'expander',
		`${alg}-solver.txt`
	)

	logger?.debug({ alg }, 'solver fetched, loading...')

	load_solver(id, circuit)

	logger?.debug({ alg }, 'solver loaded')
}

export function makeWorkerPool(
	maxWorkers: number,
	initWorker: () => Promise<WorkerChannel>,
): WorkerPool {
	let pool: Promise<WorkerChannel>[] = []
	let nextIdx = 0

	return {
		getNext() {
			if(pool.length < maxWorkers) {
				pool.push(initWorker())
			}

			const worker = pool[nextIdx]
			nextIdx = (nextIdx + 1) % pool.length

			return worker
		},
		async release() {
			const _pool = pool
			pool = []

			for(const worker of _pool) {
				const _res = await worker.catch(() => undefined)
				_res?.close()
			}
		},
	}
}