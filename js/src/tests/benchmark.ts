import { randomBytes } from 'crypto'
import { Bench } from 'tinybench'
import { CONFIG } from '../config'
import { EncryptionAlgorithm, PrivateInput, PublicInput, ZKOperator } from '../types'
import { generateZkWitness } from '../zk'
import { ALL_ZK_ENGINES, encryptData, ZK_ENGINES } from './utils'

const ALL_ALGOS: EncryptionAlgorithm[] = [
	'chacha20',
	//'aes-256-ctr',
	//'aes-128-ctr',
]

const DATA_LENGTH = 512

const BENCHES = ALL_ALGOS.map((algo) => {
	let bench = new Bench({
		name: `Generate Proof - ${algo}`,
		iterations: 1,
		time: 5000
	})

	for(const engine of ZK_ENGINES) {
		const operator = ALL_ZK_ENGINES[engine](algo)
		let witnesses: Uint8Array[]
		bench = bench.add(
			engine,
			async() => {
				try {
					const now = Date.now()
					await Promise.all(
						witnesses.map((witness) => (
							operator.groth16Prove(witness)
						))
					)
					const elapsed = Date.now() - now
					console.log(
						`Generated ${witnesses.length} proofs for ${algo} using ${engine}, ${elapsed}ms`
					)
				} catch(err) {
					console.error(err)
				}
			},
			{
				beforeEach: async() => {
					witnesses = await prepareDataForAlgo(algo, operator)
					console.log(
						`Prepared ${witnesses.length} witnesses for ${algo} using ${engine}`
					)
				},
			}
		)
	}

	return bench
})

async function main() {
	for(const bench of BENCHES) {
		await bench.run()

		console.log(bench.name)
		console.table(bench.table())
	}
}

async function prepareDataForAlgo(
	algo: EncryptionAlgorithm,
	operator: ZKOperator
) {
	const { keySizeBytes, chunkSize, bitsPerWord } = CONFIG[algo]
	const plaintext = new Uint8Array(randomBytes(DATA_LENGTH))
	const privateInput: PrivateInput = {
		key: Buffer.alloc(keySizeBytes, 2),
	}

	const iv = new Uint8Array(12).fill(0)

	const ciphertext = encryptData(
		algo,
		plaintext,
		privateInput.key,
		iv
	)

	const witnesses: Uint8Array[] = []
	const chunkSizeBytes = chunkSize * bitsPerWord / 8

	for(let i = 0; i < ciphertext.length; i += chunkSizeBytes) {
		const publicInput: PublicInput = {
			ciphertext: ciphertext.subarray(i, i + chunkSizeBytes),
			iv: iv,
			offset: i
		}
		const { witness } = await generateZkWitness({
			algorithm: algo,
			privateInput,
			publicInput,
			operator
		})

		witnesses.push(witness)
	}

	return witnesses
}

main()

