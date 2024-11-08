import { CONFIG } from '../config'
import { makeLocalFileFetch } from '../file-fetch'
import { makeGnarkOPRFOperator } from '../gnark/toprf'
import { TOPRFResponseData } from '../gnark/types'
import { strToUint8Array } from '../gnark/utils'
import { ZKProofInputOPRF } from '../types'
import { uint8ArrayToBits } from '../utils'
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

		const { isLittleEndian } = CONFIG['chacha20']

		const respParams: any[] = []
		for(const { index, publicKeyShare, evaluated, c, r } of resps) {
			const rp = {
				index: serialiseCounter(index),
				publicKeyShare: uint8ArrayToBits(publicKeyShare),
				evaluated: uint8ArrayToBits(evaluated),
				c: uint8ArrayToBits(c),
				r: uint8ArrayToBits(r),
			}
			respParams.push(rp)
		}

		const toprfParams = {
			pos: serialiseCounter(pos), //pos in plaintext
			len: serialiseCounter(len), // length of data to "hash"
			domainSeparator: uint8ArrayToBits(strToUint8Array(domainSeparator)),
			output: uint8ArrayToBits(nullifier),
			responses: respParams
		}

		const witnessParams: ZKProofInputOPRF = {
			key: uint8ArrayToBits(key),
			nonce: uint8ArrayToBits(iv),
			counter: serialiseCounter(1),
			in: uint8ArrayToBits(ciphertext),
			out: [], // plaintext will be calculated in library
			mask: uint8ArrayToBits(req.mask),
			toprf: toprfParams
		}

		const wtns = await operator.generateWitness(witnessParams)
		const proof = await operator.groth16Prove(wtns)

		const verifySignals = {
			nonce: witnessParams.nonce,
			counter: witnessParams.counter,
			in: witnessParams.in,
			out:[],
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

		function serialiseCounter(counter) {
			const counterArr = new Uint8Array(4)
			const counterView = new DataView(counterArr.buffer)
			counterView.setUint32(0, counter, isLittleEndian)

			return uint8ArrayToBits(counterArr)
		}
	})
})