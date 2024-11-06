import { Base64 } from 'js-base64'
import { makeLocalFileFetch } from '../file-fetch'
import { makeLocalGnarkOPRFOperator } from '../gnark/toprf'
import { encryptData } from './utils'

describe('TOPRF circuits Tests', () => {

	it('should prove & verify TOPRF', async() => {
		const fetcher = makeLocalFileFetch()
		const operator = makeLocalGnarkOPRFOperator(fetcher)

		const email = 'test@email.com'
		const domainSeparator = 'reclaim'

		const keys = await operator.GenerateThresholdKeys(3, 2)

		const req = await operator.generateOPRFRequestData(email, domainSeparator)

		const resps: [] = []
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

		const result = await operator.TOPRFFinalize(keys.publicKey, req, resps)
		//console.log(result.output) // actual hash to be used elsewhere


		const pos = 10
		const len = email.length


		// response from OPRF servers + local values
		// pre-calculated for email & separator above
		const toprf = {
			pos: pos, //pos in plaintext
			len: len, // length of data to "hash"
			mask: req.mask,
			domainSeparator: Base64.fromUint8Array(new Uint8Array(Buffer.from(domainSeparator))),
			output: result.output, // => hashing this produces that "oprf hash" or nullifier that we need
			responses: resps
		}


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

		const witnessParams = {
			'cipher': 'chacha20-toprf',
			'key': key,
			'nonce': iv,
			'counter': 1,
			'input': ciphertext, // plaintext will be calculated in library
			'toprf': toprf
		}


		const wtns = await operator.generateWitness(witnessParams)

		const proof = await operator.proveOPRF(wtns)

		const verifySignals = {
			'nonce': iv,
			'counter': 1,
			'input': ciphertext,
			'toprf': {
				pos: pos, //pos in plaintext
				len: len, // length of data to "hash"
				domainSeparator: toprf.domainSeparator,
				output: toprf.output,
				responses: resps
			}
		}

		expect(await operator.verifyOPRF(verifySignals, proof)).toEqual(true)
	})
})