import { Base64 } from 'js-base64'
import { CONFIG } from '../config'
import { EncryptionAlgorithm } from '../types'

const BIN_PATH = '../../bin/gnark'

export type GnarkLib = {
	verify: Function
	free: Function
	prove: Function
	initAlgorithm: Function
	koffi: typeof import('koffi')
}

export const ALGS_MAP: {
	[key in EncryptionAlgorithm]: { ext: string }
} = {
	'chacha20': { ext: 'chacha20' },
	'aes-128-ctr': { ext: 'aes128' },
	'aes-256-ctr': { ext: 'aes256' },
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
			prove: libProve.func('Prove', ProveReturn, [GoSlice]),
			initAlgorithm: libProve.func(
				'InitAlgorithm', 'unsigned char',
				['unsigned char', GoSlice, GoSlice]
			),
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
		counter: deSerialiseCounter(),
		input: Base64.fromUint8Array(bitsToUint8Array(input.in.flat())),
	}

	const paramsJson = JSON.stringify(proofParams)
	return strToUint8Array(paramsJson)

	function deSerialiseCounter() {
		const bytes = bitsToUint8Array(input.counter)
		const counterView = new DataView(bytes.buffer)
		return counterView.getUint32(0, isLittleEndian)
	}
}