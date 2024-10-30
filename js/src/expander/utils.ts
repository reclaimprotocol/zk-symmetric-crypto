import { EncryptionAlgorithm, FileFetch, Logger } from '../types'
import init, { is_circuit_loaded, is_solver_loaded, load_circuit, load_solver } from './wasm-binding'

const BIN_NAME = 'release'

type DataMap = { [_: string]: Uint8Array | (number | bigint)[] }
type WitnessParams = {
	public: DataMap
	private: DataMap
}

export async function loadExpander(
	fetcher: FileFetch,
	logger?: Logger
) {
	const buff = await fetcher
		.fetch('expander', `${BIN_NAME}.wasm`, logger)
	await init({ 'module_or_path': buff })
}

const FIELD_SIZE = 32
const USIZE = 8

export function calculateWitness({
	public: publicData,
	private: privateData,
}: WitnessParams) {
	const pub = serialiseData(publicData)
	const priv = serialiseData(privateData)
	const wtns = new Uint8Array(
		USIZE // num witnesses (1)
		+ USIZE // num priv inputs
		+ USIZE // num pub inputs
		+ USIZE * 4 // modulus
		+ priv.serialised.length
		+ pub.serialised.length
	)
	const dataview = new DataView(
		wtns.buffer, wtns.byteOffset, wtns.byteLength
	)

	let offset = 0
	offset = writeUint64(dataview, offset, 1)
	offset = writeUint64(dataview, offset, priv.valueCount)
	offset = writeUint64(dataview, offset, pub.valueCount)
	offset = writeFieldSerde(dataview, offset, 0)

	wtns.set(priv.serialised, offset)
	offset += priv.serialised.length

	wtns.set(pub.serialised, offset)
	offset += pub.serialised.length

	return wtns
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

/**
 * Serialises all values in the data object, in order,
 * into a single Uint8Array. Will use 32 bytes for each
 * value, and will pad with zeroes if the value is not
 * exactly 32 bytes.
 */
function serialiseData(data: DataMap) {
	const values = Object.values(data)
		.flatMap((key) => Array.isArray(key) ? key : Array.from(key))
	const serialised = new Uint8Array(values.length * 32)
	const dataview = new DataView(serialised.buffer)

	let offset = 0
	for(const value of values) {
		offset = writeFieldSerde(dataview, offset, value)
	}

	return { serialised, valueCount: values.length }
}

function writeFieldSerde(
	dataview: DataView,
	offset: number,
	value: number | bigint,
) {
	dataview.setBigUint64(offset, BigInt(value), true)
	return offset + FIELD_SIZE
}

function writeUint64(dataview: DataView, offset: number, value: number) {
	dataview.setBigUint64(offset, BigInt(value), true)
	return offset + USIZE
}