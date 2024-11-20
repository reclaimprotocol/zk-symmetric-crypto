import { Base64, fromUint8Array, toUint8Array } from 'js-base64'
import * as koffi from 'koffi'
import { EncryptionAlgorithm, KeyShare, Logger, MakeZKOperatorOpts, OPRFOperator } from '../types'
import { executeGnarkFn, executeGnarkFnAndGetJson, initGnarkAlgorithm, serialiseGnarkWitness } from './utils'

const ALGS_MAP: {
	[key in EncryptionAlgorithm]: {
		ext: string
		id: number
	}
} = {
	'chacha20': { ext: 'chacha20_oprf', id: 3 },
	'aes-128-ctr': { ext: 'aes128_oprf', id: 4 },
	'aes-256-ctr': { ext: 'aes256_oprf', id: 5 },
}

export function makeGnarkOPRFOperator({
	fetcher,
	algorithm
}: MakeZKOperatorOpts<{}>): OPRFOperator {
	return {
		async generateWitness(input) {
			return serialiseGnarkWitness(algorithm, input)
		},
		async groth16Prove(witness, logger) {
			const lib = await initGnark(logger)
			const {
				proof: { proofJson }
			} = await executeGnarkFnAndGetJson(lib.prove, witness)
			return { proof: Base64.toUint8Array(proofJson) }
		},
		async groth16Verify(publicSignals, proof, logger) {
			const lib = await initGnark(logger)
			const pubSignals = serialiseGnarkWitness(algorithm, publicSignals)

			const verifyParams = JSON.stringify({
				cipher: `${algorithm}-toprf`,
				proof: typeof proof === 'string'
					? proof
					: Base64.fromUint8Array(proof),
				publicSignals: Base64.fromUint8Array(pubSignals),
			})
			return executeGnarkFn(lib.verify, verifyParams) === 1
		},
		async generateThresholdKeys(total, threshold, logger) {
			const lib = await initGnark(logger)
			const { generateThresholdKeys, vfree } = lib

			const params = { total: total, threshold: threshold }
			const res = executeGnarkFn(generateThresholdKeys, JSON.stringify(params))
			const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString()
			vfree(res.r0) // Avoid memory leak!
			const parsed = JSON.parse(resJson)

			const shares: KeyShare[] = []
			for(let i = 0; i < parsed.shares.length; i++) {
				const share = parsed.shares[i]
				shares.push({
					index:share.index,
					publicKey: toUint8Array(share.publicKey),
					privateKey: toUint8Array(share.privateKey),
				})
			}

			return {
				publicKey: toUint8Array(parsed.publicKey),
				privateKey: toUint8Array(parsed.privateKey),
				shares: shares,
			}
		},
		async generateOPRFRequestData(data, domainSeparator, logger) {
			const lib = await initGnark(logger)
			const params = {
				data: Base64.fromUint8Array(data),
				domainSeparator: domainSeparator,
			}

			const parsed = await executeGnarkFnAndGetJson(
				lib.generateOPRFRequest,
				JSON.stringify(params)
			)

			return {
				mask: toUint8Array(parsed.mask),
				maskedData: toUint8Array(parsed.maskedData),
				secretElements: [
					toUint8Array(parsed.secretElements[0]),
					toUint8Array(parsed.secretElements[1])
				]
			}
		},
		async finaliseOPRF(serverPublicKey, request, responses, logger) {
			const lib = await initGnark(logger)
			const params = {
				serverPublicKey: fromUint8Array(serverPublicKey),
				request: {
					mask: fromUint8Array(request.mask),
					maskedData: fromUint8Array(request.maskedData),
					secretElements: [
						fromUint8Array(request.secretElements[0]),
						fromUint8Array(request.secretElements[1])
					]
				},
				responses: responses.map(({ publicKeyShare, evaluated, c, r }) => (
					{
						publicKeyShare: fromUint8Array(publicKeyShare),
						evaluated: fromUint8Array(evaluated),
						c: fromUint8Array(c),
						r: fromUint8Array(r),
					}
				))
			}

			const parsed = await executeGnarkFnAndGetJson(
				lib.toprfFinalize,
				JSON.stringify(params)
			)
			return toUint8Array(parsed.output)
		},
		async evaluateOPRF(serverPrivate, maskedData, logger) {
			const lib = await initGnark(logger)

			const { oprfEvaluate, vfree } = lib
			const params = {
				serverPrivate: fromUint8Array(serverPrivate),
				maskedData: fromUint8Array(maskedData),
			}
			const res = executeGnarkFn(oprfEvaluate, JSON.stringify(params))
			const resJson = Buffer.from(
				koffi.decode(res.r0, 'unsigned char', res.r1)
			).toString()
			vfree(res.r0) // Avoid memory leak!
			const parsed = JSON.parse(resJson)
			return {
				evaluated: toUint8Array(parsed.evaluated),
				c: toUint8Array(parsed.c),
				r: toUint8Array(parsed.r),
			}
		},
	}

	async function initGnark(logger?: Logger) {
		const { ext, id } = ALGS_MAP[algorithm]
		return initGnarkAlgorithm(id, ext, fetcher, logger)
	}
}


