import assert from 'assert'
import { describe, it } from 'node:test'
import { CONFIG } from '../config.ts'
import { makeLocalFileFetch } from '../file-fetch.ts'
import { makeGnarkOPRFOperator } from '../gnark/toprf.ts'
import { strToUint8Array } from '../gnark/utils.ts'
import type { EncryptionAlgorithm, OPRFOperator, OPRFResponseData, ZKEngine, ZKTOPRFPublicSignals } from '../types.ts'
import { ceilToBlockSizeMultiple, getBlockSizeBytes } from '../utils.ts'
import { generateProof, verifyProof } from '../zk.ts'

const fetcher = makeLocalFileFetch()
const threshold = 1

const POSITIONS = [
	0,
	10
]

type Config = {
	make: (alg: EncryptionAlgorithm) => OPRFOperator
	algorithms: EncryptionAlgorithm[]
}

const OPRF_ZK_ENGINES_MAP: { [E in ZKEngine]?: Config } = {
	'gnark': {
		make: algorithm => makeGnarkOPRFOperator({ fetcher, algorithm }),
		algorithms: ['chacha20', 'aes-128-ctr', 'aes-256-ctr'],
	}
}

const OPRF_ENGINES = Object.keys(OPRF_ZK_ENGINES_MAP) as ZKEngine[]
const OPRF_TEST_MATRIX = OPRF_ENGINES.flatMap(engine => (
	OPRF_ZK_ENGINES_MAP[engine]!.algorithms
		.map(algorithm => ({ engine, algorithm }))
))

for(const { engine, algorithm } of OPRF_TEST_MATRIX) {
	const { make } = OPRF_ZK_ENGINES_MAP[engine]!
	describe(`${engine} - ${algorithm} TOPRF circuits Tests`, () => {
		const operator = make(algorithm)

		for(const pos of POSITIONS) {
			it(`should prove & verify TOPRF at pos=${pos}`, async() => {
				const email = 'test@email.com'
				const domainSeparator = 'reclaim'

				const keys = await operator.generateThresholdKeys(5, threshold)
				const req = await operator
					.generateOPRFRequestData(strToUint8Array(email), domainSeparator)

				const resps: OPRFResponseData[] = []
				for(let i = 0; i < threshold; i++) {
					const evalResult = await operator.evaluateOPRF(
						keys.shares[i].privateKey,
						req.maskedData
					)

					resps.push({
						publicKeyShare: keys.shares[i].publicKey,
						evaluated: evalResult.evaluated,
						c: evalResult.c,
						r: evalResult.r,
					})
				}

				const nullifier = await operator
					.finaliseOPRF(keys.publicKey, req, resps)
				const len = email.length

				const plaintext = new Uint8Array(Buffer.alloc(64))
				//replace part of plaintext with email
				plaintext.set(new Uint8Array(Buffer.from(email)), pos)

				const { keySizeBytes, encrypt } = CONFIG[algorithm]
				const key = new Uint8Array(Array.from(Array(keySizeBytes).keys()))
				const iv = new Uint8Array(Array.from(Array(12).keys()))

				const ciphertext = await encrypt({ in: plaintext, key, iv })

				const toprf: ZKTOPRFPublicSignals = {
					locations: [
						{
							pos: pos, //pos in plaintext
							len: len, // length of data to "hash"
						}
					],
					domainSeparator,
					output: nullifier,
					responses: resps
				}

				const proof = await generateProof({
					algorithm,
					privateInput: {
						key,
					},
					publicInput: { iv, ciphertext },
					operator,
					mask: req.mask,
					toprf,
				})
				assert.ok(!proof.plaintext)

				await verifyProof({
					proof,
					publicInput: { iv, ciphertext },
					toprf,
					operator
				})
			})
		}

		it('should prove OPRF spread across blocks with multi nonces', async() => {
			const email = 'test@email.com'
			const domainSeparator = 'reclaim'

			const keys = await operator.generateThresholdKeys(5, threshold)
			const req = await operator
				.generateOPRFRequestData(strToUint8Array(email), domainSeparator)

			const resps: OPRFResponseData[] = []
			for(let i = 0; i < threshold; i++) {
				const evalResult = await operator
					.evaluateOPRF(keys.shares[i].privateKey, req.maskedData)

				resps.push({
					publicKeyShare: keys.shares[i].publicKey,
					evaluated: evalResult.evaluated,
					c: evalResult.c,
					r: evalResult.r,
				})
			}

			const nullifier = await operator
				.finaliseOPRF(keys.publicKey, req, resps)

			const blockSize = getBlockSizeBytes(algorithm)
			const blocksPerChunk = CONFIG[algorithm].blocksPerChunk
			const chunkSize = blockSize * blocksPerChunk
			const plaintext1 = new Uint8Array(Buffer.alloc(chunkSize - 8))
			// replace part of plaintext with email, such that the first
			// few bytes are at the end of the first plaintext block
			// and the rest is in the next block
			const emailInFirstBlock = email.slice(0, 5)
			const pos = plaintext1.length - emailInFirstBlock.length - 1
			plaintext1.set(Buffer.from(emailInFirstBlock), pos)

			const plaintext2 = new Uint8Array(email.length)
			plaintext2.set(Buffer.from(email.slice(emailInFirstBlock.length)))

			const { keySizeBytes, encrypt } = CONFIG[algorithm]
			const key = new Uint8Array(Array.from(Array(keySizeBytes).keys()))
			const iv1 = new Uint8Array(Array.from(Array(12).keys()))
			const iv2
				= new Uint8Array(Array.from(Array(12).keys()).map(i => i + 1))

			const ciphertext1
				= await encrypt({ in: plaintext1, key, iv: iv1 })
			const ciphertext2
				= await encrypt({ in: plaintext2, key, iv: iv2 })

			const textOffset = blockSize
			const toprf: ZKTOPRFPublicSignals = {
				locations: [
					{
						pos: pos - textOffset, //pos in plaintext
						len: emailInFirstBlock.length, // length of data to "hash"
					},
					{
						pos: ceilToBlockSizeMultiple(pos - textOffset, algorithm),
						len: email.length - emailInFirstBlock.length
					}
				],
				domainSeparator,
				output: nullifier,
				responses: resps
			}

			const publicInput = [
				{
					iv: iv1,
					ciphertext: ciphertext1.slice(textOffset),
					offsetBytes: textOffset,
				},
				{ iv: iv2, ciphertext: ciphertext2 }
			]
			const proof = await generateProof({
				algorithm,
				privateInput: { key },
				publicInput,
				operator,
				mask: req.mask,
				toprf,
			})

			await verifyProof({ proof, publicInput, toprf, operator })
		})
	})
}