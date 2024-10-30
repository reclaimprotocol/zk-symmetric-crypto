import { randomBytes } from 'crypto'
import {
	CONFIG,
	EncryptionAlgorithm,
	generateProof,
	makeGnarkZkOperator,
	makeLocalFileFetch,
	makeSnarkJsZKOperator,
	PrivateInput,
	verifyProof,
	ZKEngine,
	ZKOperator,
} from '../index'
import { encryptData } from './utils'

jest.setTimeout(20_000)

const ALL_ALGOS: EncryptionAlgorithm[] = [
	'chacha20',
	'aes-256-ctr',
	'aes-128-ctr',
]

const ALG_TEST_CONFIG = {
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

const fetcher = makeLocalFileFetch()

const ALL_ZK_ENGINES: {
	[E in ZKEngine]: (algorithm: EncryptionAlgorithm) => ZKOperator
} = {
	'snarkjs': (algorithm) => (
		makeSnarkJsZKOperator({ algorithm, fetcher })
	),
	'gnark': (algorithm) => (
		makeGnarkZkOperator({ algorithm, fetcher })
	),
}

const ZK_ENGINES = Object.keys(ALL_ZK_ENGINES) as ZKEngine[]

describe.each(ALL_ALGOS)('%s Lib Tests', (algorithm) => {
	describe.each(ZK_ENGINES)('%s engine', (zkEngine) => {
		const {
			encLength,
		} = ALG_TEST_CONFIG[algorithm]
		const {
			bitsPerWord,
			chunkSize,
			keySizeBytes
		} = CONFIG[algorithm]

		const chunkSizeBytes = chunkSize * bitsPerWord / 8

		let operator: ZKOperator
		beforeAll(async() => {
			operator = await ALL_ZK_ENGINES[zkEngine](algorithm)
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
			const publicInput = { ciphertext, iv: iv, offset: 0 }

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
			// use a chunk in the middle
			const offset = 2

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
				.subarray(chunkSizeBytes * offset, chunkSizeBytes * (offset + 1))

			const publicInput = { ciphertext, iv, offset }
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
			const publicInput = { ciphertext, iv, offset: 0 }

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

			await expect(
				verifyProof({ proof, publicInput, operator })
			).rejects.toHaveProperty('message', 'invalid proof')
		})
	})


})