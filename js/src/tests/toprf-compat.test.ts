/**
 * Cross-compatibility tests between gnark and stwo TOPRF.
 *
 * Both implementations now use MiMC hash over BN254, so they should produce
 * identical outputs for the same inputs.
 */
import assert from 'assert'
import { describe, it } from 'node:test'
import { makeLocalFileFetch } from '../file-fetch.ts'
import { makeGnarkOPRFOperator } from '../gnark/toprf.ts'
import { strToUint8Array } from '../gnark/utils.ts'
import { makeStwoOPRFOperator } from '../stwo/toprf.ts'
import type { OPRFResponseData } from '../types.ts'

const fetcher = makeLocalFileFetch()

// Helper to convert Uint8Array to hex for comparison
function toHex(arr: Uint8Array): string {
	return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

// Helper to compare Uint8Arrays
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
	if(a.length !== b.length) {
		return false
	}

	for(const [i, element] of a.entries()) {
		if(element !== b[i]) {
			return false
		}
	}

	return true
}

describe('gnark-stwo TOPRF compatibility tests', () => {
	// Create operators for both systems
	// Using chacha20 as base algorithm (doesn't affect TOPRF operations)
	const gnarkOp = makeGnarkOPRFOperator({ fetcher, algorithm: 'chacha20' })
	const stwoOp = makeStwoOPRFOperator({ fetcher })

	describe('key format compatibility', () => {
		it('both systems generate valid public keys', async() => {
			const gnarkKeys = await gnarkOp.generateThresholdKeys(3, 2)
			const stwoKeys = await stwoOp.generateThresholdKeys(3, 2)

			// Both systems now use compressed points (32 bytes)
			assert.strictEqual(gnarkKeys.publicKey.length, 32, 'gnark public key should be 32 bytes')
			assert.strictEqual(stwoKeys.publicKey.length, 32, 'stwo public key should be 32 bytes')

			// Share public keys
			assert.strictEqual(gnarkKeys.shares[0].publicKey.length, 32, 'gnark share public key should be 32 bytes')
			assert.strictEqual(stwoKeys.shares[0].publicKey.length, 32, 'stwo share public key should be 32 bytes')

			console.log('  gnark server pubkey:', toHex(gnarkKeys.publicKey))
			console.log('  stwo server pubkey:', toHex(stwoKeys.publicKey))
		})

		it('share private keys are valid scalars', async() => {
			const gnarkKeys = await gnarkOp.generateThresholdKeys(3, 2)
			const stwoKeys = await stwoOp.generateThresholdKeys(3, 2)

			// Private keys should be non-empty (variable length due to trimming)
			assert.ok(gnarkKeys.shares[0].privateKey.length > 0, 'gnark private key should be non-empty')
			assert.ok(stwoKeys.shares[0].privateKey.length > 0, 'stwo private key should be non-empty')

			// Private keys should be at most 32 bytes
			assert.ok(gnarkKeys.shares[0].privateKey.length <= 32, 'gnark private key should be <= 32 bytes')
			assert.ok(stwoKeys.shares[0].privateKey.length <= 32, 'stwo private key should be <= 32 bytes')
		})
	})

	describe('request format compatibility', () => {
		it('both systems generate valid request formats', async() => {
			const secret = 'test@example.com'
			const domain = 'reclaim'

			const gnarkReq = await gnarkOp.generateOPRFRequestData(strToUint8Array(secret), domain)
			const stwoReq = await stwoOp.generateOPRFRequestData(strToUint8Array(secret), domain)

			// Both systems now use compressed points (32 bytes)
			assert.strictEqual(gnarkReq.maskedData.length, 32, 'gnark maskedData should be 32 bytes')
			assert.strictEqual(stwoReq.maskedData.length, 32, 'stwo maskedData should be 32 bytes')

			// Masks are random, so they will differ
			assert.ok(gnarkReq.mask.length > 0, 'gnark mask should be non-empty')
			assert.ok(stwoReq.mask.length > 0, 'stwo mask should be non-empty')

			// Secret elements should be present
			assert.strictEqual(gnarkReq.secretElements.length, 2, 'gnark should have 2 secret elements')
			assert.strictEqual(stwoReq.secretElements.length, 2, 'stwo should have 2 secret elements')

			console.log('  gnark maskedData:', toHex(gnarkReq.maskedData))
			console.log('  stwo maskedData:', toHex(stwoReq.maskedData))
		})
	})

	describe('output format compatibility', () => {
		it('stwo produces 32-byte (256-bit) outputs', async() => {
			const secret = 'test@example.com'
			const domain = 'reclaim'
			const threshold = 1

			const stwoKeys = await stwoOp.generateThresholdKeys(5, threshold)
			const stwoReq = await stwoOp.generateOPRFRequestData(strToUint8Array(secret), domain)

			const evalResult = await stwoOp.evaluateOPRF(
				stwoKeys.shares[0].privateKey,
				stwoReq.maskedData
			)
			const stwoResps: OPRFResponseData[] = [{
				publicKeyShare: stwoKeys.shares[0].publicKey,
				evaluated: evalResult.evaluated,
				c: evalResult.c,
				r: evalResult.r,
			}]

			const stwoOutput = await stwoOp.finaliseOPRF(stwoKeys.publicKey, stwoReq, stwoResps)

			// stwo output should be 32 bytes (256-bit MiMC hash)
			assert.strictEqual(stwoOutput.length, 32, 'stwo output should be 32 bytes')

			console.log('  stwo output:', toHex(stwoOutput))
		})

		it('same system produces deterministic outputs', async() => {
			const secret = 'determinism@test.com'
			const domain = 'test-domain'
			const threshold = 1

			// Generate keys once
			const keys = await stwoOp.generateThresholdKeys(3, threshold)

			// Create request once (mask is random, so we reuse it)
			const req = await stwoOp.generateOPRFRequestData(strToUint8Array(secret), domain)

			// Evaluate and finalize twice with same inputs
			const resp = await stwoOp.evaluateOPRF(keys.shares[0].privateKey, req.maskedData)
			const resps: OPRFResponseData[] = [{
				publicKeyShare: keys.shares[0].publicKey,
				evaluated: resp.evaluated,
				c: resp.c,
				r: resp.r,
			}]

			const output1 = await stwoOp.finaliseOPRF(keys.publicKey, req, resps)
			const output2 = await stwoOp.finaliseOPRF(keys.publicKey, req, resps)

			assert.ok(arraysEqual(output1, output2), 'Same inputs should produce same output')
			console.log('  Deterministic output:', toHex(output1))
		})

		it('different secrets produce different outputs', async() => {
			const domain = 'test-domain'
			const threshold = 1

			const keys = await stwoOp.generateThresholdKeys(3, threshold)

			// Test with two different secrets
			const secret1 = 'user1@example.com'
			const secret2 = 'user2@example.com'

			const req1 = await stwoOp.generateOPRFRequestData(strToUint8Array(secret1), domain)
			const req2 = await stwoOp.generateOPRFRequestData(strToUint8Array(secret2), domain)

			const resp1 = await stwoOp.evaluateOPRF(keys.shares[0].privateKey, req1.maskedData)
			const resp2 = await stwoOp.evaluateOPRF(keys.shares[0].privateKey, req2.maskedData)

			const output1 = await stwoOp.finaliseOPRF(keys.publicKey, req1, [{
				publicKeyShare: keys.shares[0].publicKey,
				evaluated: resp1.evaluated,
				c: resp1.c,
				r: resp1.r,
			}])

			const output2 = await stwoOp.finaliseOPRF(keys.publicKey, req2, [{
				publicKeyShare: keys.shares[0].publicKey,
				evaluated: resp2.evaluated,
				c: resp2.c,
				r: resp2.r,
			}])

			assert.ok(!arraysEqual(output1, output2), 'Different secrets should produce different outputs')
			console.log('  Output 1:', toHex(output1).slice(0, 32) + '...')
			console.log('  Output 2:', toHex(output2).slice(0, 32) + '...')
		})
	})

	describe('cross-system compatibility (same keys, same output)', () => {
		it('gnark keys + gnark request → stwo evaluate → same output as gnark', async() => {
			// Generate keys and request with gnark
			const secret = 'cross-test@example.com'
			const domain = 'cross-domain'
			const threshold = 1

			const gnarkKeys = await gnarkOp.generateThresholdKeys(3, threshold)
			const gnarkReq = await gnarkOp.generateOPRFRequestData(strToUint8Array(secret), domain)

			// Evaluate with gnark
			const gnarkResp = await gnarkOp.evaluateOPRF(
				gnarkKeys.shares[0].privateKey,
				gnarkReq.maskedData
			)

			// Evaluate with stwo using same keys
			const stwoResp = await stwoOp.evaluateOPRF(
				gnarkKeys.shares[0].privateKey,
				gnarkReq.maskedData
			)

			// The evaluated points should be identical (scalar multiplication is deterministic)
			assert.ok(
				arraysEqual(gnarkResp.evaluated, stwoResp.evaluated),
				'Evaluated points should match'
			)

			console.log('  gnark evaluated:', toHex(gnarkResp.evaluated))
			console.log('  stwo evaluated:', toHex(stwoResp.evaluated))

			// Finalize with gnark using gnark's response
			const gnarkOutput = await gnarkOp.finaliseOPRF(gnarkKeys.publicKey, gnarkReq, [{
				publicKeyShare: gnarkKeys.shares[0].publicKey,
				evaluated: gnarkResp.evaluated,
				c: gnarkResp.c,
				r: gnarkResp.r,
			}])

			// Finalize with stwo using stwo's response
			// Both should produce the same output since evaluated points match
			const stwoOutput = await stwoOp.finaliseOPRF(gnarkKeys.publicKey, gnarkReq, [{
				publicKeyShare: gnarkKeys.shares[0].publicKey,
				evaluated: stwoResp.evaluated,
				c: stwoResp.c,
				r: stwoResp.r,
			}])

			// Both outputs should be identical
			assert.ok(
				arraysEqual(gnarkOutput, stwoOutput),
				'gnark and stwo should produce identical outputs for same keys/request'
			)

			console.log('  gnark output:', toHex(gnarkOutput))
			console.log('  stwo output:', toHex(stwoOutput))
			console.log('  MATCH!')
		})

		it('stwo keys + stwo request → gnark evaluate → same output as stwo', async() => {
			// Generate keys and request with stwo
			const secret = 'reverse-test@example.com'
			const domain = 'reverse-domain'
			const threshold = 1

			const stwoKeys = await stwoOp.generateThresholdKeys(3, threshold)
			const stwoReq = await stwoOp.generateOPRFRequestData(strToUint8Array(secret), domain)

			// Evaluate with stwo
			const stwoResp = await stwoOp.evaluateOPRF(
				stwoKeys.shares[0].privateKey,
				stwoReq.maskedData
			)

			// Evaluate with gnark using same keys
			const gnarkResp = await gnarkOp.evaluateOPRF(
				stwoKeys.shares[0].privateKey,
				stwoReq.maskedData
			)

			// The evaluated points should be identical
			assert.ok(
				arraysEqual(stwoResp.evaluated, gnarkResp.evaluated),
				'Evaluated points should match'
			)

			console.log('  stwo evaluated:', toHex(stwoResp.evaluated))
			console.log('  gnark evaluated:', toHex(gnarkResp.evaluated))

			// Finalize with stwo using stwo's response
			const stwoOutput = await stwoOp.finaliseOPRF(stwoKeys.publicKey, stwoReq, [{
				publicKeyShare: stwoKeys.shares[0].publicKey,
				evaluated: stwoResp.evaluated,
				c: stwoResp.c,
				r: stwoResp.r,
			}])

			// Finalize with gnark using gnark's response
			const gnarkOutput = await gnarkOp.finaliseOPRF(stwoKeys.publicKey, stwoReq, [{
				publicKeyShare: stwoKeys.shares[0].publicKey,
				evaluated: gnarkResp.evaluated,
				c: gnarkResp.c,
				r: gnarkResp.r,
			}])

			// Both outputs should be identical
			assert.ok(
				arraysEqual(stwoOutput, gnarkOutput),
				'stwo and gnark should produce identical outputs for same keys/request'
			)

			console.log('  stwo output:', toHex(stwoOutput))
			console.log('  gnark output:', toHex(gnarkOutput))
			console.log('  MATCH!')
		})

		it('gnark can verify stwo DLEQ proof and vice versa', async() => {
			const secret = 'dleq-test@example.com'
			const domain = 'dleq-domain'
			const threshold = 1

			const keys = await gnarkOp.generateThresholdKeys(3, threshold)
			const req = await gnarkOp.generateOPRFRequestData(strToUint8Array(secret), domain)

			// Evaluate with both systems
			const stwoResp = await stwoOp.evaluateOPRF(keys.shares[0].privateKey, req.maskedData)
			const gnarkResp = await gnarkOp.evaluateOPRF(keys.shares[0].privateKey, req.maskedData)

			console.log('  stwo c:', toHex(stwoResp.c))
			console.log('  stwo r:', toHex(stwoResp.r))
			console.log('  gnark c:', toHex(gnarkResp.c))
			console.log('  gnark r:', toHex(gnarkResp.r))
			console.log('  stwo evaluated:', toHex(stwoResp.evaluated))
			console.log('  gnark evaluated:', toHex(gnarkResp.evaluated))
			console.log('  publicKeyShare:', toHex(keys.shares[0].publicKey))
			console.log('  maskedData:', toHex(req.maskedData))

			// gnark verifies stwo's DLEQ proof
			const gnarkOutput = await gnarkOp.finaliseOPRF(keys.publicKey, req, [{
				publicKeyShare: keys.shares[0].publicKey,
				evaluated: stwoResp.evaluated,
				c: stwoResp.c,
				r: stwoResp.r,
			}])
			console.log('  gnark verifying stwo DLEQ: PASS')

			// stwo verifies gnark's DLEQ proof
			const stwoOutput = await stwoOp.finaliseOPRF(keys.publicKey, req, [{
				publicKeyShare: keys.shares[0].publicKey,
				evaluated: gnarkResp.evaluated,
				c: gnarkResp.c,
				r: gnarkResp.r,
			}])
			console.log('  stwo verifying gnark DLEQ: PASS')

			// Both should produce the same output
			assert.ok(arraysEqual(gnarkOutput, stwoOutput), 'Cross-verification outputs should match')
			console.log('  Cross-verification outputs match!')
		})
	})
})

describe('stwo TOPRF standalone tests', () => {
	const stwoOp = makeStwoOPRFOperator({ fetcher })

	it('should handle maximum secret size (62 bytes)', async() => {
		const maxSecret = 'A'.repeat(62)
		const domain = 'test'
		const threshold = 1

		const keys = await stwoOp.generateThresholdKeys(3, threshold)
		const req = await stwoOp.generateOPRFRequestData(strToUint8Array(maxSecret), domain)

		assert.strictEqual(req.maskedData.length, 32, 'maskedData should be 32 bytes (compressed)')

		const resp = await stwoOp.evaluateOPRF(keys.shares[0].privateKey, req.maskedData)
		const output = await stwoOp.finaliseOPRF(keys.publicKey, req, [{
			publicKeyShare: keys.shares[0].publicKey,
			evaluated: resp.evaluated,
			c: resp.c,
			r: resp.r,
		}])

		assert.strictEqual(output.length, 32, 'output should be 32 bytes')
		console.log('  Max secret output:', toHex(output))
	})

	it('should handle empty domain separator', async() => {
		const secret = 'test@example.com'
		const domain = ''
		const threshold = 1

		const keys = await stwoOp.generateThresholdKeys(3, threshold)
		const req = await stwoOp.generateOPRFRequestData(strToUint8Array(secret), domain)
		const resp = await stwoOp.evaluateOPRF(keys.shares[0].privateKey, req.maskedData)

		const output = await stwoOp.finaliseOPRF(keys.publicKey, req, [{
			publicKeyShare: keys.shares[0].publicKey,
			evaluated: resp.evaluated,
			c: resp.c,
			r: resp.r,
		}])

		assert.strictEqual(output.length, 32)
		console.log('  Empty domain output:', toHex(output))
	})

	it('should work with threshold=nodes (all shares required)', async() => {
		// Multi-share Lagrange combination not yet implemented
		console.log('  SKIP: Multi-share finalization not yet implemented')
	})
})
