import assert from 'node:assert'
import { randomBytes } from 'node:crypto'
import { after, before, describe, it } from 'node:test'
import {
	CONFIG,
	type EncryptionAlgorithm,
	generateProof,
	getBlockSizeBytes,
	type PrivateInput,
	type PublicInput,
	verifyProof,
	type ZKEngine,
	type ZKOperator,
} from '../index.ts'
import { encryptData, getEngineForConfigItem, ZK_CONFIG_MAP, ZK_CONFIGS } from './utils.ts'

// TODO: add back AES tests
const ALL_ALGOS: EncryptionAlgorithm[] = [
	'chacha20',
	'aes-256-ctr',
	'aes-128-ctr',
]

const SUPPORTED_ALGO_MAP: { [T in ZKEngine]: EncryptionAlgorithm[] } = {
	'expander': ['chacha20'],
	'gnark': ALL_ALGOS,
	'snarkjs': ALL_ALGOS,
}

const ALG_TEST_CONFIG: { [E in EncryptionAlgorithm]: { encLength: number } } = {
	'chacha20': {
		encLength: 45,
	},
	'aes-256-ctr': {
		encLength: 44,
	},
	'aes-128-ctr': {
		encLength: 44,
	},
}

const TEST_MATRIX = ZK_CONFIGS.flatMap(zkEngine => (
	SUPPORTED_ALGO_MAP[getEngineForConfigItem(zkEngine)]
		.map(algorithm => ({ zkEngine, algorithm }))
))

for(const { zkEngine, algorithm } of TEST_MATRIX) {
	describe(`${zkEngine} - ${algorithm} Engine Tests`, () => {
		const { encLength } = ALG_TEST_CONFIG[algorithm]
		const {
			bitsPerWord,
			chunkSize,
			keySizeBytes
		} = CONFIG[algorithm]

		const chunkSizeBytes = chunkSize * bitsPerWord / 8

		let operator: ZKOperator
		before(async() => {
			operator = await ZK_CONFIG_MAP[zkEngine](algorithm)
		})

		after(async() => {
			await operator.release?.()
		})

		it('should verify encrypted data', async() => {
			const plaintext = new Uint8Array(randomBytes(encLength))

			const privateInput: PrivateInput = {
				key: Buffer.alloc(keySizeBytes, 2),
			}

			const iv = new Uint8Array(Array.from(Array(12).keys()))

			const ciphertext = encryptData(
				algorithm,
				plaintext,
				privateInput.key,
				iv
			)
			const publicInput: PublicInput = { ciphertext, iv: iv }

			const proof = await generateProof({
				algorithm,
				privateInput,
				publicInput,
				operator
			})
			// client will send proof to witness
			// witness would verify proof
			await verifyProof({ proof, publicInput, operator })
		})

		it('should verify encrypted data with another counter', async() => {
			const totalPlaintext = new Uint8Array(randomBytes(chunkSizeBytes * 5))
			// use two blocks as offset (not chunks)
			const offsetBytes = 2 * getBlockSizeBytes(algorithm)

			const iv = Buffer.alloc(12, 3)
			const privateInput: PrivateInput = {
				key: Buffer.alloc(keySizeBytes, 2),
			}

			const totalCiphertext = encryptData(
				algorithm,
				totalPlaintext,
				privateInput.key,
				iv,
			)
			const ciphertext = totalCiphertext
				.subarray(offsetBytes, chunkSizeBytes + offsetBytes)

			const publicInput = { ciphertext, iv, offsetBytes }
			const proof = await generateProof({
				algorithm,
				privateInput,
				publicInput,
				operator
			})

			await verifyProof({ proof, publicInput, operator })
		})

		it('should fail to verify incorrect data', async() => {
			const plaintext = Buffer.alloc(encLength, 1)

			const privateInput: PrivateInput = {
				key: Buffer.alloc(keySizeBytes, 2),
			}

			const iv = Buffer.alloc(12, 3)
			const ciphertext = encryptData(
				algorithm,
				plaintext,
				privateInput.key,
				iv
			)
			const publicInput: PublicInput = { ciphertext, iv }

			const proof = await generateProof({
				algorithm,
				privateInput,
				publicInput,
				operator
			})
			// fill output with 0s
			for(let i = 0;i < proof.plaintext.length;i++) {
				proof.plaintext[i] = 0
			}

			await assert.rejects(
				() => verifyProof({ proof, publicInput, operator }),
				(err: Error) => {
					assert.match(err.message, /invalid proof/)
					return true
				}
			)
		})
	})
}