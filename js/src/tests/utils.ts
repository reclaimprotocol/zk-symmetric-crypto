import { wasm as WasmTester } from 'circom_tester'
import { createCipheriv } from 'crypto'
import { cpus } from 'os'
import { join } from 'path'
import {
	EncryptionAlgorithm,
	makeExpanderZkOperator,
	makeGnarkZkOperator,
	makeLocalFileFetch,
	makeSnarkJsZKOperator,
	ZKOperator
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

type ConfigItem = 'snarkjs'
	| 'gnark'
	| 'expander-single-thread'
	| 'expander-multi-thread'

export function getEngineForConfigItem(item: ConfigItem) {
	return item === 'snarkjs'
		? 'snarkjs'
		: (
			item === 'gnark'
				? 'gnark'
				: 'expander'
		)
}

export const ZK_CONFIG_MAP: {
	[E in ConfigItem]: (algorithm: EncryptionAlgorithm) => ZKOperator
} = {
	'snarkjs': (algorithm) => (
		makeSnarkJsZKOperator({
			algorithm,
			fetcher,
			options: { maxProofConcurrency: 2 }
		})
	),
	'gnark': (algorithm) => (
		makeGnarkZkOperator({ algorithm, fetcher })
	),
	'expander-single-thread': (algorithm) => (
		makeExpanderZkOperator({
			algorithm,
			fetcher,
			options: { maxWorkers: 0 }
		})
	),
	'expander-multi-thread': (algorithm) => (
		makeExpanderZkOperator({
			algorithm,
			fetcher,
			options: { maxWorkers: cpus().length }
		})
	),
}

export const ZK_CONFIGS = Object.keys(ZK_CONFIG_MAP) as ConfigItem[]