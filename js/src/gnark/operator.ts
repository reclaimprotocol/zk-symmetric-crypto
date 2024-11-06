import { Base64 } from 'js-base64'
import { CONFIG } from '../config'
import { Logger, MakeZKOperatorOpts, ZKOperator } from '../types'
import { ALGS_MAP, generateGnarkWitness, loadGnarkLib, strToUint8Array } from './utils'

export let globalGnarkLib: ReturnType<typeof loadGnarkLib> | undefined

export function makeGnarkZkOperator({
	algorithm,
	fetcher
}: MakeZKOperatorOpts<{}>): ZKOperator {
	let initDone = false

	return {
		async generateWitness(input): Promise<Uint8Array> {
			return generateGnarkWitness(algorithm, input)
		},
		async groth16Prove(witness, logger) {
			const lib = await initGnark(logger)

			const { prove, koffi, free } = lib
			const wtns = {
				data: Buffer.from(witness),
				len:witness.length,
				cap:witness.length
			}
			const res = prove(wtns)
			const proofJson = Buffer.from(
				koffi.decode(res.r0, 'unsigned char', res.r1)
			).toString()
			free(res.r0) // Avoid memory leak!
			return JSON.parse(proofJson)
		},
		async groth16Verify(publicSignals, proof, logger) {
			const lib = await initGnark(logger)

			const { bitsToUint8Array } = CONFIG[algorithm]

			const proofStr = proof['proofJson']
			const verifyParams = {
				cipher: algorithm,
				proof: proofStr,
				publicSignals: Base64.fromUint8Array(
					bitsToUint8Array(publicSignals.flat())
				),
			}

			const paramsJson = JSON.stringify(verifyParams)
			const paramsBuf = strToUint8Array(paramsJson)

			const params = {
				data: paramsBuf,
				len:paramsJson.length,
				cap:paramsJson.length
			}

			return lib.verify(params) === 1
		},
	}

	async function initGnark(logger?: Logger) {
		globalGnarkLib ||= loadGnarkLib()
		const lib = await globalGnarkLib
		if(initDone) {
			return lib
		}

		const { ext } = ALGS_MAP[algorithm]
		const { index: id } = CONFIG[algorithm]
		const [pk, r1cs] = await Promise.all([
			fetcher.fetch('gnark', `pk.${ext}`, logger),
			fetcher.fetch('gnark', `r1cs.${ext}`, logger),
		])

		const f1 = { data: pk, len: pk.length, cap: pk.length }
		const f2 = { data: r1cs, len: r1cs.length, cap: r1cs.length }

		await lib.initAlgorithm(id, f1, f2)

		initDone = true

		return lib
	}
}