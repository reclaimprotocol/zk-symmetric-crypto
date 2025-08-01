import { randomBytes } from 'crypto'
import {
	CONFIG,
	EncryptionAlgorithm,
	generateProof,
	getBlockSizeBytes,
	PrivateInput,
	PublicInput,
	verifyProof,
	ZKEngine,
	ZKOperator,
} from '../index'
import {
	encryptData,
	getEngineForConfigItem,
	ZK_CONFIG_MAP,
	ZK_CONFIGS,
} from './utils'

jest.setTimeout(90_000)

// TODO: add back AES tests
const ALL_ALGOS: EncryptionAlgorithm[] = [
	'chacha20',
	'aes-256-ctr',
	'aes-128-ctr',
]

const SUPPORTED_ALGO_MAP: { [T in ZKEngine]: EncryptionAlgorithm[] } = {
	// TODO: impl more algos for barretenberg
	barretenberg: ['chacha20', 'aes-128-ctr'],
	expander: ['chacha20'],
	gnark: ALL_ALGOS,
	snarkjs: ALL_ALGOS,
}

const ALG_TEST_CONFIG: { [E in EncryptionAlgorithm] } = {
	chacha20: {
		encLength: 45,
	},
	'aes-256-ctr': {
		encLength: 44,
	},
	'aes-128-ctr': {
		encLength: 44,
	},
}

describe.each(ZK_CONFIGS)('%s Engine Tests', (zkEngine) => {
	if(zkEngine !== 'barretenberg') {
		return
	}

	const ALGOS = SUPPORTED_ALGO_MAP[getEngineForConfigItem(zkEngine)]
	describe.each(ALGOS)('%s Lib Tests', (algorithm) => {
		const { encLength } = ALG_TEST_CONFIG[algorithm]
		const { bitsPerWord, chunkSize, keySizeBytes } = CONFIG[algorithm]

		const chunkSizeBytes = (chunkSize * bitsPerWord) / 8

		let operator: ZKOperator
		beforeAll(async() => {
			operator = await ZK_CONFIG_MAP[zkEngine](algorithm)
		})

		afterEach(async() => {
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
				operator,
			})
			// client will send proof to witness
			// witness would verify proof
			await verifyProof({ proof, publicInput, operator })
		})

		it('should verify encrypted with static plaintext', async() => {
			// 76,  97, 100, 105, 101, 115,  32,  97,
			// 110, 100,  32,  71, 101, 110, 116, 108,
			// 101, 109, 101, 110,  32, 111, 102,  32,
			// 116, 104, 101,  32,  99, 108,  97, 115,
			// 115,  32, 111, 102
			const text = 'Ladies and Gentlemen of the class of'
			const plaintext = Uint8Array.from(text.split('').map(char => char.charCodeAt(0)))

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
				operator,
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
				iv
			)
			const ciphertext = totalCiphertext.subarray(
				offsetBytes,
				chunkSizeBytes + offsetBytes
			)

			const publicInput = { ciphertext, iv, offsetBytes }
			const proof = await generateProof({
				algorithm,
				privateInput,
				publicInput,
				operator,
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
				operator,
			})
			if(zkEngine === 'barretenberg') {
				(proof.proofData as Uint8Array)[0] = ((proof.proofData as Uint8Array)[0] + 1) % 256
			} else {
				for(let i = 0; i < proof.plaintext.length; i++) {
					proof.plaintext[i] = 0
				}
			}

			await expect(
				verifyProof({ proof, publicInput, operator })
			).rejects.toHaveProperty('message', 'invalid proof')
		})
	})
})
