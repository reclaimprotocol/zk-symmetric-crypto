import { CONFIG } from '../config'
import { makeLocalFileFetch } from '../file-fetch'
import { makeGnarkOPRFOperator } from '../gnark/toprf'
import { strToUint8Array } from '../gnark/utils'
import { EncryptionAlgorithm, OPRFOperator, OPRFResponseData, ZKEngine, ZKTOPRFPublicSignals } from '../types'
import { generateProof, verifyProof } from '../zk'
import { encryptData } from './utils'

jest.setTimeout(10_000)

const fetcher = makeLocalFileFetch()
const threshold = 1

const POSITIONS = [
	0,
	10
]

type Config = {
	make: (alg: EncryptionAlgorithm) => OPRFOperator
	algorithms: EncryptionAlgorithm[]
}

const OPRF_ZK_ENGINES_MAP: { [E in ZKEngine]?: Config } = {
	'gnark': {
		make: algorithm => makeGnarkOPRFOperator({ fetcher, algorithm }),
		algorithms: ['chacha20', 'aes-128-ctr', 'aes-256-ctr'],
	}
}

const OPRF_ENGINES = Object.keys(OPRF_ZK_ENGINES_MAP) as ZKEngine[]

describe.each(OPRF_ENGINES)('%s TOPRF circuits Tests', engine => {

	const { make, algorithms } = OPRF_ZK_ENGINES_MAP[engine]!

	describe.each(algorithms)('%s', algorithm => {

		const operator = make(algorithm)

		it.each(POSITIONS)('should prove & verify TOPRF at pos=%s', async pos => {
			const email = 'test@email.com'
			const domainSeparator = 'reclaim'

			const keys = await operator.generateThresholdKeys(5, threshold)
			const req = await operator
				.generateOPRFRequestData(strToUint8Array(email), domainSeparator)

			const resps: OPRFResponseData[] = []
			for(let i = 0; i < threshold; i++) {
				const evalResult = await operator.evaluateOPRF(
					keys.shares[i].privateKey,
					req.maskedData
				)

				resps.push({
					publicKeyShare: keys.shares[i].publicKey,
					evaluated: evalResult.evaluated,
					c: evalResult.c,
					r: evalResult.r,
				})
			}

			const nullifier = await operator
				.finaliseOPRF(keys.publicKey, req, resps)
			const len = email.length

			const plaintext = new Uint8Array(Buffer.alloc(64))
			//replace part of plaintext with email
			plaintext.set(new Uint8Array(Buffer.from(email)), pos)

			const { keySizeBytes } = CONFIG[algorithm]
			const key = new Uint8Array(Array.from(Array(keySizeBytes).keys()))
			const iv = new Uint8Array(Array.from(Array(12).keys()))

			const ciphertext = encryptData(algorithm, plaintext, key, iv)

			const toprf: ZKTOPRFPublicSignals = {
				pos: pos, //pos in plaintext
				len: len, // length of data to "hash"
				domainSeparator,
				output: nullifier,
				responses: resps
			}

			const proof = await generateProof({
				algorithm,
				privateInput: {
					key,
				},
				publicInput: {
					iv,
					ciphertext,
					offset: 0
				},
				operator,
				mask: req.mask,
				toprf,
			})

			await expect(
				verifyProof({
					proof,
					publicInput: { iv, ciphertext,
						offset: 0
					},
					toprf,
					operator
				})
			).resolves.toBeUndefined()
		})
	})
})