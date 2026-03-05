import assert from 'node:assert'
import { randomBytes } from 'node:crypto'
import { after, before, describe, it } from 'node:test'
import { makeLocalFileFetch } from '../file-fetch.ts'
import { CONFIG, type EncryptionAlgorithm, type ZKOperator } from '../index.ts'
import { makeStwoZkOperator } from '../stwo/operator.ts'

const fetcher = makeLocalFileFetch()

// Stwo requires block-aligned data:
// - ChaCha20: multiple of 64 bytes
// - AES-CTR: multiple of 16 bytes
const STWO_TEST_CONFIG: { [E in EncryptionAlgorithm]: { blockSize: number } } = {
	'chacha20': { blockSize: 64 },
	'aes-256-ctr': { blockSize: 16 },
	'aes-128-ctr': { blockSize: 16 },
}

for(const algorithm of ['chacha20', 'aes-256-ctr', 'aes-128-ctr'] as EncryptionAlgorithm[]) {
	describe(`stwo - ${algorithm} direct tests`, () => {
		const { blockSize } = STWO_TEST_CONFIG[algorithm]
		const { keySizeBytes, encrypt, startCounter } = CONFIG[algorithm]

		let operator: ZKOperator
		before(async() => {
			operator = makeStwoZkOperator({ algorithm, fetcher })
		})

		after(() => {
			operator.release?.()
		})

		it('should prove and verify single block', async() => {
			const plaintext = new Uint8Array(randomBytes(blockSize))
			const key = new Uint8Array(randomBytes(keySizeBytes))
			const nonce = new Uint8Array(randomBytes(12))

			const ciphertext = await encrypt({ in: plaintext, key, iv: nonce })

			// Create witness directly (bypassing zk.ts logic)
			const witness = await operator.generateWitness({
				key,
				noncesAndCounters: [{ nonce, counter: startCounter, boundary: undefined }],
				in: ciphertext.slice(0, blockSize),
				out: plaintext,
			})

			const { proof } = await operator.groth16Prove(witness)
			assert.ok(proof, 'proof should be generated')
			assert.ok(proof.length > 0, 'proof should have content')

			// Verify
			const verified = await operator.groth16Verify(
				{
					noncesAndCounters: [{ nonce, counter: startCounter, boundary: undefined }],
					in: ciphertext.slice(0, blockSize),
					out: plaintext,
				},
				proof
			)
			assert.strictEqual(verified, true, 'proof should verify')
		})

		it('should prove and verify multiple blocks', async() => {
			const numBlocks = 4
			const dataSize = blockSize * numBlocks
			const plaintext = new Uint8Array(randomBytes(dataSize))
			const key = new Uint8Array(randomBytes(keySizeBytes))
			const nonce = new Uint8Array(randomBytes(12))

			const ciphertext = await encrypt({ in: plaintext, key, iv: nonce })

			const witness = await operator.generateWitness({
				key,
				noncesAndCounters: [{ nonce, counter: startCounter, boundary: undefined }],
				in: ciphertext.slice(0, dataSize),
				out: plaintext,
			})

			const { proof } = await operator.groth16Prove(witness)
			assert.ok(proof, 'proof should be generated')

			const verified = await operator.groth16Verify(
				{
					noncesAndCounters: [{ nonce, counter: startCounter, boundary: undefined }],
					in: ciphertext.slice(0, dataSize),
					out: plaintext,
				},
				proof
			)
			assert.strictEqual(verified, true, 'proof should verify')
		})

		it('should fail with invalid ciphertext', async() => {
			const plaintext = new Uint8Array(randomBytes(blockSize))
			const key = new Uint8Array(randomBytes(keySizeBytes))
			const nonce = new Uint8Array(randomBytes(12))

			// Create fake ciphertext that doesn't match
			const fakeCiphertext = new Uint8Array(randomBytes(blockSize))

			const witness = await operator.generateWitness({
				key,
				noncesAndCounters: [{ nonce, counter: startCounter, boundary: undefined }],
				in: fakeCiphertext,
				out: plaintext,
			})

			await assert.rejects(
				async() => operator.groth16Prove(witness),
				/Ciphertext does not match encryption/,
				'should reject invalid witness'
			)
		})

		it('should fail verification with corrupted proof', async() => {
			const plaintext = new Uint8Array(randomBytes(blockSize))
			const key = new Uint8Array(randomBytes(keySizeBytes))
			const nonce = new Uint8Array(randomBytes(12))

			const ciphertext = await encrypt({ in: plaintext, key, iv: nonce })

			// Generate a valid proof
			const witness = await operator.generateWitness({
				key,
				noncesAndCounters: [{ nonce, counter: startCounter, boundary: undefined }],
				in: ciphertext.slice(0, blockSize),
				out: plaintext,
			})

			const { proof } = await operator.groth16Prove(witness)

			// Corrupt the proof by modifying some bytes
			const corruptedProof = proof.slice(0, -10) + 'XXXXXXXXXX'

			const verified = await operator.groth16Verify(
				{
					noncesAndCounters: [{ nonce, counter: startCounter, boundary: undefined }],
					in: ciphertext.slice(0, blockSize),
					out: plaintext,
				},
				corruptedProof
			)
			assert.strictEqual(verified, false, 'verification should fail with corrupted proof')
		})
	})
}
