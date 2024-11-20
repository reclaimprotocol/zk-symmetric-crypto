import { makeLocalFileFetch } from '../file-fetch'
import { makeGnarkOPRFOperator } from '../gnark/toprf'
import { strToUint8Array } from '../gnark/utils'
import { OPRFResponseData, ZKTOPRFPublicSignals } from '../types'
import { generateProof, verifyProof } from '../zk'
import { encryptData } from './utils'

const fetcher = makeLocalFileFetch()
const operator = makeGnarkOPRFOperator({ fetcher, algorithm: 'chacha20' })
const threshold = 1

const POSITIONS = [
	0,
	10
]

describe('TOPRF circuits Tests', () => {

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

		const key = new Uint8Array(Array.from(Array(32).keys()))
		const iv = new Uint8Array(Array.from(Array(12).keys()))

		const ciphertext = encryptData('chacha20', plaintext, key, iv)

		const toprf: ZKTOPRFPublicSignals = {
			pos: pos, //pos in plaintext
			len: len, // length of data to "hash"
			domainSeparator,
			output: nullifier,
			responses: resps
		}

		const proof = await generateProof({
			algorithm: 'chacha20',
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
				publicInput: {
					iv,
					ciphertext,
					offset: 0
				},
				toprf,
				operator
			})
		).resolves.toBeUndefined()
	})
})