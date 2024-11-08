import { makeLocalFileFetch } from '../file-fetch'
import { makeGnarkOPRFOperator } from '../gnark/toprf'
import { TOPRFResponseData } from '../gnark/types'
import { strToUint8Array } from '../gnark/utils'
import { ZKProofInputOPRF, ZKProofPublicSignalsOPRF } from '../types'
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

		const plaintext = new Uint8Array(Buffer.alloc(128)) //2 blocks
		//replace part of plaintext with email
		plaintext.set(new Uint8Array(Buffer.from(email)), pos)

		const key = new Uint8Array(Array.from(Array(32).keys()))
		const iv = new Uint8Array(Array.from(Array(12).keys()))

		const ciphertext = encryptData('chacha20', plaintext, key, iv)

		const respParams: any[] = []
		for(const { index, publicKeyShare, evaluated, c, r } of resps) {
			const rp = {
				index: index,
				publicKeyShare: publicKeyShare,
				evaluated: evaluated,
				c: c,
				r: r,
			}
			respParams.push(rp)
		}

		const domainSeparatorArr = strToUint8Array(domainSeparator)
		const witnessParams: ZKProofInputOPRF = {
			key: key,
			nonce: iv,
			counter: 1,
			in: ciphertext,
			out: new Uint8Array(), // plaintext will be calculated in library
			mask: req.mask,
			toprf: {
				pos: pos, //pos in plaintext
				len: len, // length of data to "hash"
				domainSeparator: domainSeparatorArr,
				output: nullifier,
				responses: respParams
			}
		}

		const wtns = await operator.generateWitness(witnessParams)
		const proof = await operator.groth16Prove(wtns)

		const verifySignals: ZKProofPublicSignalsOPRF = {
			nonce: witnessParams.nonce,
			counter: witnessParams.counter,
			in: witnessParams.in,
			out: new Uint8Array(),
			toprf: {
				pos: witnessParams.toprf.pos,
				len: witnessParams.toprf.len,
				domainSeparator: witnessParams.toprf.domainSeparator,
				output: witnessParams.toprf.output,
				responses: witnessParams.toprf.responses
			}
		}

		expect(
			await operator.groth16Verify(verifySignals, proof.proof)
		).toEqual(true)
	})
})