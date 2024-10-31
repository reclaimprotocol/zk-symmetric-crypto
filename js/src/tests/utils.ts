import { wasm as WasmTester } from 'circom_tester'
import { createCipheriv } from 'crypto'
import { join } from 'path'
import {
	EncryptionAlgorithm, 	makeExpanderZkOperator,
	makeGnarkZkOperator,
	makeLocalFileFetch,
	makeSnarkJsZKOperator,
	ZKEngine, ZKOperator
} from '../index'

export function encryptData(
	algorithm: EncryptionAlgorithm,
	plaintext: Uint8Array,
	key: Uint8Array,
	iv: Uint8Array
) {
	// chacha20 encrypt
	const cipher = createCipheriv(
		algorithm === 'chacha20'
			? 'chacha20-poly1305'
			: (
				algorithm === 'aes-256-ctr'
					? 'aes-256-gcm'
					: 'aes-128-gcm'
			),
		key,
		iv,
	)
	return Buffer.concat([
		cipher.update(plaintext),
		cipher.final()
	])
}

export function loadCircuit(name: string) {
	return WasmTester(join(__dirname, `../../circuits/tests/${name}.circom`))
}

const fetcher = makeLocalFileFetch()

export const ALL_ZK_ENGINES: {
	[E in Exclude<ZKEngine, 'snarkjs'>]: (algorithm: EncryptionAlgorithm) => ZKOperator
} = {
	// 'snarkjs': (algorithm) => (
	// 	makeSnarkJsZKOperator({ algorithm, fetcher })
	// ),
	'expander': (algorithm) => (
		makeExpanderZkOperator({ algorithm, fetcher })
	),
	'gnark': (algorithm) => (
		makeGnarkZkOperator({ algorithm, fetcher })
	),
}

export const ZK_ENGINES = Object.keys(ALL_ZK_ENGINES) as ZKEngine[]