import { isMainThread, parentPort, Worker, workerData } from 'worker_threads'
import type { Logger } from '../types'
import type { ErrorRPCMessage, RPCMessageMap, WorkerChannel, WorkerInitData } from './types'
import init, { prove } from './wasm-binding.js'

const BYTES_PER_PAGE = 65536
const logger: Logger = console

async function main() {
	const { module, initialisationMemory } = workerData as WorkerInitData
	const wasm = await init({ 'module_or_path': module })

	const growthRequired = (
		initialisationMemory.byteLength - wasm.memory.buffer.byteLength
	) / BYTES_PER_PAGE

	if(growthRequired > 0) {
		wasm.memory.grow(growthRequired)
		logger.debug({ growthRequired }, 'memory grown')
	}

	// copy initialisation memory
	const memory = new Uint8Array(wasm.memory.buffer)
	memory.set(initialisationMemory)

	logger.debug('worker initialised w memory')

	parentPort!.on('message', async(msg) => {
		const [type, input] = msg as Parameters<WorkerChannel['rpc']>
		if(type === 'prove') {
			try {
				const result = await prove(...input.args)
				sendOutputRpcBack({ id: input.id!, result })

				logger.debug({ id: input.id }, 'prove done')
			} catch(err) {
				logger.error({ err }, 'prove error')
				sendOutputRpcBack({
					id: input.id!,
					type: 'error',
					message: err.message,
					stack: err.stack
				})
			}

			return
		}

		throw new Error(`Unknown message type: ${type}`)
	})

	parentPort!.postMessage({ type: 'online' })

	function sendOutputRpcBack<T extends keyof RPCMessageMap>(
		output: RPCMessageMap[T]['output'] | ErrorRPCMessage
	) {
		parentPort!.postMessage(['reply', output])
	}
}

export async function initWorker(workerData: WorkerInitData) {
	const worker = new Worker(__filename, { workerData })
	await new Promise<void>((resolve, reject) => {
		worker.once('message', resolve)
		worker.once('error', reject)
	})

	const channel: WorkerChannel = {
		rpc(type, input) {
			input.id ||= createRpcId()

			const wait = waitForRpcReply<
				RPCMessageMap[typeof type]['output']
			>(input.id)
			worker.postMessage([type, input])
			return wait
		},
		close() {
			return worker.terminate()
		}
	}

	return channel

	async function waitForRpcReply<T>(id: string) {
		return new Promise<T>((resolve, reject) => {
			worker.on('message', listener)
			worker.once('error', reject)

			async function listener([type, output]: any) {
				if(type !== 'reply' || output.id !== id) {
					return
				}

				worker.off('message', listener)
				worker.off('error', reject)

				if(output.type === 'error') {
					const err = new Error(output.message)
					err.stack = output.stack
					reject(err)
					return
				}

				resolve(output)
			}
		})
	}
}

function createRpcId() {
	return Math.random().toString(36).slice(2)
}

if(!isMainThread) {
	main()
}
