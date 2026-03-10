import { describe, it } from 'node:test'
import { CONFIG } from '../config.ts'
import { strToUint8Array } from '../gnark/utils.ts'
import {
	debug_combined_toprf,
	debug_toprf_verify,
	generate_cipher_toprf_proof,
	toprf_create_request,
	toprf_evaluate,
	toprf_finalize,
	toprf_generate_keys,
} from '../stwo/s2circuits-wrapper.ts'

function uint8ArrayToHex(arr: Uint8Array): string {
	return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

describe('Stwo TOPRF debug', () => {
	it('should trace maskedData computation', async() => {
		const email = 'test@email.com'
		const domainSeparator = 'reclaim'
		const pos = 0

		// Generate keys
		const keysJson = toprf_generate_keys(5, 1)
		const keys = JSON.parse(keysJson)
		console.log('Keys generated')

		// Create request
		const emailBytes = strToUint8Array(email)
		const reqJson = toprf_create_request(emailBytes, domainSeparator)
		const req = JSON.parse(reqJson)
		console.log('\n=== TOPRF Create Request ===')
		console.log('mask:', req.mask)
		console.log('maskedData:', req.maskedData)
		console.log('secretElements[0]:', req.secretElements[0])
		console.log('secretElements[1]:', req.secretElements[1])

		// Evaluate
		const share = keys.shares[0]
		const evalJson = toprf_evaluate(JSON.stringify({ index: share.index, privateKey: share.privateKey, publicKey: share.publicKey }), req.maskedData)
		const evalResult = JSON.parse(evalJson)
		console.log('\n=== TOPRF Evaluate ===')
		console.log('evaluated:', evalResult.evaluated)
		console.log('c:', evalResult.c)
		console.log('r:', evalResult.r)

		// Finalize
		const finalizeParams = {
			serverPublicKey: keys.serverPublicKey,
			request: req,
			responses: [evalResult],
		}
		const finalJson = toprf_finalize(JSON.stringify(finalizeParams))
		const finalResult = JSON.parse(finalJson)
		console.log('\n=== TOPRF Finalize ===')
		console.log('output:', finalResult.output)

		// Now compute via debug_combined_toprf - simulating extract_secret_data
		const plaintext = new Uint8Array(64)
		plaintext.set(emailBytes, pos)

		const debugJson = debug_combined_toprf(
			plaintext,
			JSON.stringify([{ pos: pos, len: email.length }]),
			domainSeparator,
			req.mask
		)
		const debug = JSON.parse(debugJson)
		console.log('\n=== debug_combined_toprf ===')
		console.log('secret_data_0:', debug.secret_data_0)
		console.log('secret_data_1:', debug.secret_data_1)
		console.log('domain_separator:', debug.domain_separator)
		console.log('data_point_x:', debug.data_point_x)
		console.log('data_point_y:', debug.data_point_y)
		console.log('mask:', debug.mask)
		console.log('masked_gnark:', debug.masked_gnark)

		// Compare
		console.log('\n=== Comparison ===')
		console.log('secretElements[0] === secret_data_0:', req.secretElements[0] === debug.secret_data_0)
		console.log('secretElements[1] === secret_data_1:', req.secretElements[1] === debug.secret_data_1)
		console.log('maskedData === masked_gnark:', req.maskedData === debug.masked_gnark)
	})

	it('should test combined proof directly', async() => {
		const email = 'test@email.com'
		const domainSeparator = 'reclaim'
		const pos = 0
		const algorithm = 'chacha20'

		// Generate keys
		const keysJson = toprf_generate_keys(5, 1)
		const keys = JSON.parse(keysJson)

		// Create request
		const emailBytes = strToUint8Array(email)
		const reqJson = toprf_create_request(emailBytes, domainSeparator)
		const req = JSON.parse(reqJson)
		console.log('\n=== Created Request ===')
		console.log('mask:', req.mask)
		console.log('maskedData:', req.maskedData)

		// Evaluate
		const share = keys.shares[0]
		const evalJson = toprf_evaluate(JSON.stringify({
			index: share.index,
			privateKey: share.privateKey,
			publicKey: share.publicKey
		}), req.maskedData)
		const evalResult = JSON.parse(evalJson)
		console.log('\n=== Evaluated ===')
		console.log('evaluated:', evalResult.evaluated)
		console.log('publicKeyShare:', evalResult.publicKeyShare)
		console.log('c:', evalResult.c)
		console.log('r:', evalResult.r)

		// Finalize to get output
		const finalizeParams = {
			serverPublicKey: keys.serverPublicKey,
			request: req,
			responses: [evalResult],
		}
		const finalJson = toprf_finalize(JSON.stringify(finalizeParams))
		const finalResult = JSON.parse(finalJson)
		console.log('\n=== Finalized ===')
		console.log('output:', finalResult.output)

		// Create plaintext with email
		const plaintext = new Uint8Array(64)
		plaintext.set(emailBytes, pos)

		// Encrypt
		const { keySizeBytes, encrypt } = CONFIG[algorithm]
		const key = new Uint8Array(Array.from(Array(keySizeBytes).keys()))
		const iv = new Uint8Array(Array.from(Array(12).keys()))
		const ciphertext = await encrypt({ in: plaintext, key, iv })

		// Build TOPRF JSON
		const toprfJson = JSON.stringify({
			locations: [{ pos: pos, len: email.length }],
			domainSeparator,
			output: '0x' + finalResult.output,
			responses: [{
				publicKeyShare: '0x' + evalResult.publicKeyShare,
				evaluated: '0x' + evalResult.evaluated,
				c: '0x' + evalResult.c,
				r: '0x' + evalResult.r,
			}],
			mask: '0x' + req.mask,
		})

		console.log('\n=== TOPRF JSON ===')
		console.log(toprfJson)

		// Get the correct starting counter from config
		const { startCounter } = CONFIG[algorithm]
		console.log('\n=== Input Summary ===')
		console.log('key:', uint8ArrayToHex(key))
		console.log('iv:', uint8ArrayToHex(iv))
		console.log('counter:', startCounter)
		console.log('plaintext length:', plaintext.length)
		console.log('ciphertext length:', ciphertext.length)
		console.log('plaintext hex:', uint8ArrayToHex(plaintext))
		console.log('ciphertext hex:', uint8ArrayToHex(ciphertext))

		// Debug TOPRF verification before generating proof
		console.log('\n=== Debug TOPRF Verify ===')
		const debugVerifyJson = debug_toprf_verify(plaintext, toprfJson)
		const debugVerify = JSON.parse(debugVerifyJson)
		console.log('DLEQ valid:', debugVerify.dleq_valid)
		console.log('masked_gnark:', debugVerify.masked_gnark)
		console.log('response_x:', debugVerify.response_x)
		console.log('response_y:', debugVerify.response_y)
		console.log('pub_key_x:', debugVerify.pub_key_x)
		console.log('pub_key_y:', debugVerify.pub_key_y)
		console.log('c:', debugVerify.c)
		console.log('r:', debugVerify.r)

		// Try to generate proof
		console.log('\n=== Generating Combined Proof ===')

		// Build blocks JSON for the new API
		const blocksJson = JSON.stringify([{
			nonce: uint8ArrayToHex(iv),
			counter: startCounter,
			byteOffset: 0,
			byteLen: plaintext.length
		}])

		const proofResult = generate_cipher_toprf_proof(
			algorithm,
			key,
			plaintext,
			ciphertext,
			blocksJson,
			toprfJson
		)
		const parsed = JSON.parse(proofResult)
		console.log('Result success:', parsed.success)
		if(parsed.error) {
			console.log('Error:', parsed.error)
		}
	})
})
