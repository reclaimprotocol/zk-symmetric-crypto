import { makeLocalFileFetch } from '../file-fetch'
import { makeGnarkOPRFOperator } from '../gnark/toprf'
import { TOPRFResponseData } from '../gnark/types'
import { ZKTOPRFPublicSignals } from '../types'
import { generateProof, verifyProof } from '../zk'
import { encryptData } from './utils'

const fetcher = makeLocalFileFetch()
const operator = makeGnarkOPRFOperator({ fetcher, algorithm: 'chacha20' })

describe('TOPRF circuits Tests', () => {

	it('should prove & verify TOPRF', async() => {
		const email = 'test@email.com'
		const domainSeparator = 'reclaim'
		const threshold = 2

		const keys = await operator.generateThresholdKeys(3, threshold)
		const req = await operator
			.generateOPRFRequestData(email, domainSeparator)

		const resps: TOPRFResponseData[] = []
		for(let i = 0; i < threshold; i++) {
			const evalResult = await operator.evaluateOPRF(
				keys.shares[i].privateKey,
				req.maskedData
			)

			const resp = {
				index: i,
				publicKeyShare: keys.shares[i].publicKey,
				evaluated: evalResult.evaluated,
				c: evalResult.c,
				r: evalResult.r,
			}

			resps.push(resp)
		}

		const nullifier = await operator
			.finaliseOPRF(keys.publicKey, req, resps)

		const pos = 10
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