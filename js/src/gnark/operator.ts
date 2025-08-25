import { Base64 } from 'js-base64'
import { CONFIG } from '../config.ts'
import type { EncryptionAlgorithm, FileFetch, Logger, MakeZKOperatorOpts, ZKOperator } from '../types.ts'
import { executeGnarkFn, executeGnarkFnAndGetJson, generateGnarkWitness, initGnarkAlgorithm, serialiseGnarkWitness } from './utils.ts'

const ALGS_MAP: {
	[key in EncryptionAlgorithm]: { ext: string }
} = {
	'chacha20': { ext: 'chacha20' },
	'aes-128-ctr': { ext: 'aes128' },
	'aes-256-ctr': { ext: 'aes256' },
}

export function makeGnarkZkOperator({
	algorithm,
	fetcher
}: MakeZKOperatorOpts<{}>): ZKOperator {
	return {
		async generateWitness(input) {
			return serialiseGnarkWitness(algorithm, input)
		},
		async groth16Prove(witness, logger) {
			const lib = await initGnark(algorithm, fetcher, logger)
			const rslt = await executeGnarkFnAndGetJson(lib.prove, witness)
			if(!('proof' in rslt) || !rslt.proof) {
				throw new Error(
					`Failed to create gnark proof: ${JSON.stringify(rslt)}`
				)
			}

			return { proof: Base64.toUint8Array(rslt.proof) }
		},
		async groth16Verify(publicSignals, proof, logger) {
			const lib = await initGnark(algorithm, fetcher, logger)
			const pubSignals = generateGnarkWitness(algorithm, publicSignals)

			const verifyParams = JSON.stringify({
				cipher: algorithm,
				proof: typeof proof === 'string'
					? proof
					: Base64.fromUint8Array(proof),
				publicSignals: pubSignals
			})
			return executeGnarkFn(lib.verify, verifyParams) === 1
		},
	}
}

export async function initGnark(
	algorithm: EncryptionAlgorithm,
	fetcher: FileFetch,
	logger?: Logger
) {
	const { ext } = ALGS_MAP[algorithm]
	const { index: id } = CONFIG[algorithm]
	return initGnarkAlgorithm(id, ext, fetcher, logger)
}