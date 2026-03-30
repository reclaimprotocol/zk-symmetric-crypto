import { makeGnarkZkOperator } from '../gnark/operator.ts'
import {
	type EncryptionAlgorithm,
	makeLocalFileFetch,
	type ZKOperator
} from '../index.ts'
import { makeSnarkJsZKOperator } from '../snarkjs/operator.ts'
import { makeStwoZkOperator } from '../stwo/operator.ts'

const fetcher = makeLocalFileFetch()

type ConfigItem = 'snarkjs'
	| 'gnark'
	| 'stwo'

export function getEngineForConfigItem(item: ConfigItem) {
	if(item === 'snarkjs') {
		return 'snarkjs'
	}

	if(item === 'stwo') {
		return 'stwo'
	}

	return 'gnark'
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
	'stwo': (algorithm) => (
		makeStwoZkOperator({ algorithm, fetcher })
	),
}

export const ZK_CONFIGS = Object.keys(ZK_CONFIG_MAP) as ConfigItem[]