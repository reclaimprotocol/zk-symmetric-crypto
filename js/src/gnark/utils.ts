import { Base64 } from 'js-base64'
import { EncryptionAlgorithm, FileFetch, Logger, ZKProofInput, ZKProofInputOPRF, ZKProofPublicSignals, ZKProofPublicSignalsOPRF, ZKTOPRFResponsePublicSignals } from '../types'

const BIN_PATH = '../../bin/gnark'

let globalGnarkLib: ReturnType<typeof loadGnarkLib> | undefined

export type GnarkLib = {
	verify: Function
	free: Function
	vfree: Function
	prove: Function
	initAlgorithm: Function
	generateThresholdKeys: Function
	oprfEvaluate: Function
	generateOPRFRequest: Function
	toprfFinalize: Function
	koffi: typeof import('koffi')
}

// golang uses different arch names
// for some archs -- so this map corrects the name
const ARCH_MAP = {
	'x64': 'x86_64',
}

const INIT_ALGS: { [key: number]: boolean } = {}

async function loadGnarkLib(): Promise<GnarkLib> {
	const koffiMod = await import('koffi')
		.catch(() => undefined)
	if(!koffiMod) {
		throw new Error('Koffi not available, cannot use gnark')
	}

	const { join } = await import('path')
	const { default: koffi } = koffiMod
	koffi.reset() //otherwise tests will fail

	// define object GoSlice to map to:
	// C type struct { void *data; GoInt len; GoInt cap; }
	const GoSlice = koffi.struct('GoSlice', {
		data: 'void *',
		len:  'longlong',
		cap: 'longlong'
	})

	const ProveReturn = koffi.struct('ProveReturn', {
		r0: 'void *',
		r1:  'longlong',
	})

	const LibReturn = koffi.struct('LibReturn', {
		r0: 'void *',
		r1:  'longlong',
	})

	const arch = ARCH_MAP[process.arch] || process.arch
	const platform = process.platform

	const libVerifyPath = join(
		__dirname,
		`${BIN_PATH}/${platform}-${arch}-libverify.so`
	)

	const libProvePath = join(
		__dirname,
		`${BIN_PATH}/${platform}-${arch}-libprove.so`
	)

	try {
		const libVerify = koffi.load(libVerifyPath)
		const libProve = koffi.load(libProvePath)

		return {
			verify: libVerify.func('Verify', 'unsigned char', [GoSlice]),
			free: libProve.func('Free', 'void', ['void *']),
			vfree: libVerify.func('VFree', 'void', ['void *']), //free in verify library
			prove: libProve.func('Prove', ProveReturn, [GoSlice]),
			initAlgorithm: libProve.func(
				'InitAlgorithm', 'unsigned char',
				['unsigned char', GoSlice, GoSlice]
			),
			generateThresholdKeys: libVerify.func('GenerateThresholdKeys', LibReturn, [GoSlice]),
			oprfEvaluate: libVerify.func('OPRFEvaluate', LibReturn, [GoSlice]),
			generateOPRFRequest: libProve.func('GenerateOPRFRequestData', LibReturn, [GoSlice]),
			toprfFinalize: libProve.func('TOPRFFinalize', LibReturn, [GoSlice]),
			koffi
		}
	} catch(err) {
		if(err.message.includes('not a mach-o')) {
			throw new Error(
				`Gnark library not compatible with OS/arch (${platform}/${arch})`
			)
		} else if(err.message.toLowerCase().includes('no such file')) {
			throw new Error(
				`Gnark library not built for OS/arch (${platform}/${arch})`
			)
		}

		throw err
	}
}

export async function initGnarkAlgorithm(
	id: number,
	fileExt: string,
	fetcher: FileFetch,
	logger?: Logger
) {
	globalGnarkLib ??= loadGnarkLib()
	const lib = await globalGnarkLib
	if(INIT_ALGS[id]) {
		return lib
	}

	const [pk, r1cs] = await Promise.all([
		fetcher.fetch('gnark', `pk.${fileExt}`, logger),
		fetcher.fetch('gnark', `r1cs.${fileExt}`, logger),
	])

	const f1 = { data: pk, len: pk.length, cap: pk.length }
	const f2 = { data: r1cs, len: r1cs.length, cap: r1cs.length }

	await lib.initAlgorithm(id, f1, f2)

	INIT_ALGS[id] = true

	return lib
}

export function strToUint8Array(str: string) {
	return new TextEncoder().encode(str)
}

export function serialiseGnarkWitness(
	cipher: EncryptionAlgorithm,
	input: ZKProofInput | ZKProofInputOPRF | ZKProofPublicSignals | ZKProofPublicSignalsOPRF
) {
	const json = generateGnarkWitness(cipher, input)
	return strToUint8Array(JSON.stringify(json))
}

export function generateGnarkWitness(
	cipher: EncryptionAlgorithm,
	input: ZKProofInput | ZKProofInputOPRF
		| ZKProofPublicSignals | ZKProofPublicSignalsOPRF
) {
	//input is bits, we convert them back to bytes
	return {
		cipher: cipher + ('toprf' in input ? '-toprf' : ''),
		key: 'key' in input
			? Base64.fromUint8Array(input.key)
			: undefined,
		nonce: Base64.fromUint8Array(input.nonce),
		counter: input.counter,
		input: Base64.fromUint8Array(input.in),
		toprf: generateTOPRFParams()
	}

	function generateTOPRFParams() {
		if(!('toprf' in input)) {
			return {}
		}

		const { pos, len, domainSeparator, output, responses } = input.toprf
		return {
			pos: pos,
			len: len,
			domainSeparator: Base64
				.fromUint8Array(strToUint8Array(domainSeparator)),
			output: Base64.fromUint8Array(output),
			responses: responses.map(mapResponse),
			mask: 'mask' in input
				? Base64.fromUint8Array(input.mask)
				: ''
		}
	}
}

function mapResponse({
	publicKeyShare, evaluated, c, r
}: ZKTOPRFResponsePublicSignals) {
	return {
		publicKeyShare: Base64.fromUint8Array(publicKeyShare),
		evaluated: Base64.fromUint8Array(evaluated),
		c: Base64.fromUint8Array(c),
		r: Base64.fromUint8Array(r),
	}
}

export function executeGnarkFn(
	fn: Function,
	jsonInput: string | Uint8Array
) {
	const wtns = {
		data: typeof jsonInput === 'string'
			? Buffer.from(jsonInput)
			: jsonInput,
		len: jsonInput.length,
		cap: jsonInput.length
	}
	return fn(wtns)
}

export async function executeGnarkFnAndGetJson(
	fn: Function,
	jsonInput: string | Uint8Array
) {
	const { free, koffi } = await globalGnarkLib!
	const res = executeGnarkFn(fn, jsonInput)
	const proofJson = Buffer.from(
		koffi.decode(res.r0, 'unsigned char', res.r1)
	).toString()
	free(res.r0) // Avoid memory leak!
	return JSON.parse(proofJson)
}