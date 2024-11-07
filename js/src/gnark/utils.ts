import { Base64 } from 'js-base64'
import { CONFIG } from '../config'
import { EncryptionAlgorithm } from '../types'

const BIN_PATH = '../../bin/gnark'

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

export const ALGS_MAP: {
	[key in EncryptionAlgorithm]: { ext: string }
} = {
	'chacha20': { ext: 'chacha20' },
	'aes-128-ctr': { ext: 'aes128' },
	'aes-256-ctr': { ext: 'aes256' },
	'chacha20-toprf': { ext: 'chacha20_oprf' },
}

// golang uses different arch names
// for some archs -- so this map corrects the name
const ARCH_MAP = {
	'x64': 'x86_64',
}

export async function loadGnarkLib(): Promise<GnarkLib> {
	const koffi = await import('koffi')
		.catch(() => undefined)
	if(!koffi) {
		throw new Error('Koffi not available, cannot use gnark')
	}

	const { join } = await import('path')

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

export function strToUint8Array(str: string) {
	return new TextEncoder().encode(str)
}

export function generateGnarkWitness(cipher: EncryptionAlgorithm, input) {
	const {
		bitsToUint8Array,
		isLittleEndian
	} = CONFIG[cipher]

	//input is bits, we convert them back to bytes
	const proofParams = {
		cipher:cipher,
		key: Base64.fromUint8Array(bitsToUint8Array(input.key.flat())),
		nonce: Base64.fromUint8Array(bitsToUint8Array(input.nonce.flat())),
		counter: deserializeNumber(input.counter),
		input: Base64.fromUint8Array(bitsToUint8Array(input.in.flat())),
		toprf: generateTOPRFParams()
	}

	const paramsJson = JSON.stringify(proofParams)
	console.log(paramsJson)
	return strToUint8Array(paramsJson)


	function generateTOPRFParams() {
		if(input.toprf) {
			const { pos, len, mask, domainSeparator, output, responses } = input.toprf
			return {
				pos: deserializeNumber(pos),
				len: deserializeNumber(len),
				mask: Base64.fromUint8Array(bitsToUint8Array(mask.flat())),
				domainSeparator: Base64.fromUint8Array(bitsToUint8Array(domainSeparator.flat())),
				output: Base64.fromUint8Array(bitsToUint8Array(output.flat())),
				responses: generateResponses(responses)
			}
		} else {
			return {}
		}
	}

	function generateResponses(responses) {
		const resps: any[] = []
		for(const {	index, publicKeyShare,	evaluated,	c,	r } of responses) {
			const resp = {
				index: deserializeNumber(index),
				publicKeyShare: Base64.fromUint8Array(bitsToUint8Array(publicKeyShare.flat())),
				evaluated: Base64.fromUint8Array(bitsToUint8Array(evaluated.flat())),
				c: Base64.fromUint8Array(bitsToUint8Array(c.flat())),
				r: Base64.fromUint8Array(bitsToUint8Array(r.flat())),
			}
			resps.push(resp)
		}

		return resps
	}

	function deserializeNumber(num) {
		const bytes = bitsToUint8Array(num)
		const counterView = new DataView(bytes.buffer)
		return counterView.getUint32(0, isLittleEndian)
	}
}