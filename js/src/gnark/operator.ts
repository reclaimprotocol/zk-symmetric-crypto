import { Base64 } from 'js-base64'
import { CONFIG } from '../config'
import { EncryptionAlgorithm, Logger, MakeZKOperatorOpts, ZKOperator } from '../types'
import { serialiseNumberTo4Bytes } from '../utils'
import { executeGnarkFn, executeGnarkFnAndGetJson, initGnarkAlgorithm, serialiseGnarkWitness } from './utils'

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
			const lib = await initGnark(logger)
			const {
				proof: { proofJson },
				publicSignals
			} = await executeGnarkFnAndGetJson(lib.prove, witness)
			return {
				proof: Base64.toUint8Array(proofJson),
				publicSignals: Array.from(Base64.toUint8Array(publicSignals))
			}
		},
		async groth16Verify(publicSignals, proof, logger) {
			const lib = await initGnark(logger)
			const pubSignals = Base64.fromUint8Array(new Uint8Array([
				...publicSignals.out,
				...publicSignals.nonce,
				...serialiseNumberTo4Bytes(algorithm, publicSignals.counter),
				...publicSignals.in
			]))

			const verifyParams = JSON.stringify({
				cipher: algorithm,
				proof: typeof proof === 'string'
					? proof
					: Base64.fromUint8Array(proof),
				publicSignals: pubSignals,
			})
			return executeGnarkFn(lib.verify, verifyParams) === 1
		},
	}

	async function initGnark(logger?: Logger) {
		const { ext } = ALGS_MAP[algorithm]
		const { index: id } = CONFIG[algorithm]
		return initGnarkAlgorithm(id, ext, fetcher, logger)
	}
}