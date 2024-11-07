import { fromUint8Array } from 'js-base64'
import { CONFIG } from '../config'
import { makeLocalFileFetch } from '../file-fetch'
import { makeGnarkZkOperator } from '../gnark/operator'
import { makeLocalGnarkTOPRFOperator } from '../gnark/toprf'
import { TOPRFResponseData } from '../gnark/types'
import { strToUint8Array } from '../gnark/utils'
import { encryptData } from './utils'

describe('TOPRF circuits Tests', () => {

	it('should prove & verify TOPRF', async() => {
		const fetcher = makeLocalFileFetch()
		const operator = makeLocalGnarkTOPRFOperator(fetcher)

		const email = 'test@email.com'
		const domainSeparator = 'reclaim'

		const keys = await operator.GenerateThresholdKeys(3, 2)

		const req = await operator.generateOPRFRequestData(email, domainSeparator)

		const resps: TOPRFResponseData[] = []
		const threshold = 2 //hardcoded

		for(let i = 0; i < threshold; i++) {
			const evalResult = await operator.OPRFEvaluate(keys.shares[i].privateKey, req.maskedData)

			const resp = {
				index: i,
				publicKeyShare: keys.shares[i].publicKey,
				evaluated: evalResult.evaluated,
				c: evalResult.c,
				r: evalResult.r,
			}

			resps.push(resp)
		}

		const nullifier = await operator.TOPRFFinalize(keys.publicKey, req, resps)


		const pos = 10
		const len = email.length

		const plaintext = new Uint8Array(Buffer.alloc(128)) //2 blocks
		plaintext.set(new Uint8Array(Buffer.from(email)), pos) //replace part of plaintext with email

		const key = new Uint8Array(Array.from(Array(32).keys()))
		const iv = new Uint8Array(Array.from(Array(12).keys()))

		const ciphertext = encryptData(
			'chacha20',
			plaintext,
			key,
			iv
		)

		const {
			isLittleEndian,
			uint8ArrayToBits,
		} = CONFIG['chacha20-toprf']


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
			mask: uint8ArrayToBits(req.mask),
			domainSeparator: uint8ArrayToBits(strToUint8Array(domainSeparator)),
			output: uint8ArrayToBits(nullifier),
			responses: respParams
		}

		const witnessParams = {
			'cipher': 'chacha20-toprf',
			key: uint8ArrayToBits(key),
			nonce: uint8ArrayToBits(iv),
			counter: serialiseCounter(1),
			in: uint8ArrayToBits(ciphertext),
			out: [], // plaintext will be calculated in library
			toprf: toprfParams
		}

		const zkOperator = makeGnarkZkOperator({ algorithm:'chacha20-toprf', fetcher })

		const wtns = await zkOperator.generateWitness(witnessParams)

		const proof = await zkOperator.groth16Prove(wtns)


		const respSignals: any[] = []
		for(const { index, publicKeyShare, evaluated, c, r } of resps) {
			const rp = {
				index: index,
				publicKeyShare: fromUint8Array(publicKeyShare),
				evaluated: fromUint8Array(evaluated),
				c: fromUint8Array(c),
				r: fromUint8Array(r),
			}
			respSignals.push(rp)
		}

		const verifySignals = {
			'nonce': fromUint8Array(iv),
			'counter': 1,
			'input': fromUint8Array(ciphertext),
			'toprf': {
				pos: pos,
				len: len,
				domainSeparator: fromUint8Array(strToUint8Array(domainSeparator)),
				output: fromUint8Array(nullifier),
				responses: respSignals
			}
		}

		expect(await zkOperator.groth16Verify(uint8ArrayToBits(strToUint8Array(JSON.stringify(verifySignals))), proof.proof)).toEqual(true)

		function serialiseCounter(counter) {
			const counterArr = new Uint8Array(4)
			const counterView = new DataView(counterArr.buffer)
			counterView.setUint32(0, counter, isLittleEndian)

			const counterBits = uint8ArrayToBits(counterArr)
				.flat()
			return counterBits
		}
	})
})