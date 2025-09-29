import { makeGnarkZkOperator } from '../gnark/operator.ts'
import {
	type EncryptionAlgorithm,
	makeLocalFileFetch,
	type ZKOperator
} from '../index.ts'
import { makeSnarkJsZKOperator } from '../snarkjs/operator.ts'

const fetcher = makeLocalFileFetch()

type ConfigItem = 'snarkjs'
	| 'gnark'

export function getEngineForConfigItem(item: ConfigItem) {
	return item === 'snarkjs'
		? 'snarkjs'
		: 'gnark'
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
}

export const ZK_CONFIGS = Object.keys(ZK_CONFIG_MAP) as ConfigItem[]