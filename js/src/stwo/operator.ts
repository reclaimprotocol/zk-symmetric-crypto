import { Base64 } from 'js-base64'
import type { EncryptionAlgorithm, FileFetch, Logger, MakeZKOperatorOpts, ZKOperator, ZKProofInput } from '../types.ts'
import * as stwoGlue from './s2circuits.js'

type StwoWasmModule = {
	generate_chacha20_proof: (key: Uint8Array, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array) => string
	generate_aes128_ctr_proof: (key: Uint8Array, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array) => string
	generate_aes256_ctr_proof: (key: Uint8Array, nonce: Uint8Array, counter: number, plaintext: Uint8Array, ciphertext: Uint8Array) => string
	verify_chacha20_proof: (proof_b64: string) => string
	verify_aes_ctr_proof: (proof_b64: string) => string
	get_circuits_info: () => string
	initSync: (module: BufferSource | { module: BufferSource }) => void
	default: (module_or_path?: BufferSource | { module_or_path: BufferSource }) => Promise<void>
}

const stwo = stwoGlue as StwoWasmModule

type StwoWitnessData = {
	algorithm: EncryptionAlgorithm
	key: string // base64
	nonce: string // base64
	counter: number
	plaintext: string // base64
	ciphertext: string // base64
}

type ProveResult = {
	success?: boolean
	error?: string
	proof?: string
	blocks?: number
	algorithm?: string
	proof_size_bytes?: number
}

type VerifyResult = {
	valid?: boolean
	error?: string
	algorithm?: string
}

let wasmInitialized = false
let initPromise: Promise<void> | undefined

async function ensureWasmInitialized(fetcher: FileFetch, logger?: Logger): Promise<void> {
	if(wasmInitialized) {
		return
	}

	if(initPromise) {
		return initPromise
	}

	initPromise = (async() => {
		const wasmBytes = await fetcher.fetch('stwo', 's2circuits_bg.wasm', logger)
		stwo.initSync({ module: wasmBytes })
		wasmInitialized = true
	})()

	return initPromise
}

function serializeWitness(algorithm: EncryptionAlgorithm, input: ZKProofInput): Uint8Array {
	const { noncesAndCounters: [{ nonce, counter }] } = input
	// Note: In the JS library, 'in' is ciphertext and 'out' is plaintext
	// Stwo expects (key, nonce, counter, plaintext, ciphertext)
	const data: StwoWitnessData = {
		algorithm,
		key: Base64.fromUint8Array(input.key),
		nonce: Base64.fromUint8Array(nonce),
		counter,
		plaintext: Base64.fromUint8Array(input.out), // out = decrypted plaintext
		ciphertext: Base64.fromUint8Array(input.in), // in = encrypted ciphertext
	}
	return new TextEncoder().encode(JSON.stringify(data))
}

function deserializeWitness(witness: Uint8Array): StwoWitnessData {
	const json = new TextDecoder().decode(witness)
	return JSON.parse(json)
}

export function makeStwoZkOperator({
	algorithm,
	fetcher,
}: MakeZKOperatorOpts<{}>): ZKOperator {
	return {
		generateWitness(input) {
			// Stwo combines witness generation and proving, so we just serialize
			// the input here to be used by groth16Prove
			return serializeWitness(algorithm, input)
		},

		async groth16Prove(witness, logger) {
			await ensureWasmInitialized(fetcher, logger)
			const data = deserializeWitness(witness)

			const key = Base64.toUint8Array(data.key)
			const nonce = Base64.toUint8Array(data.nonce)
			const plaintext = Base64.toUint8Array(data.plaintext)
			const ciphertext = Base64.toUint8Array(data.ciphertext)

			let resultJson: string
			switch (data.algorithm) {
			case 'chacha20':
				resultJson = stwo.generate_chacha20_proof(key, nonce, data.counter, plaintext, ciphertext)
				break
			case 'aes-128-ctr':
				resultJson = stwo.generate_aes128_ctr_proof(key, nonce, data.counter, plaintext, ciphertext)
				break
			case 'aes-256-ctr':
				resultJson = stwo.generate_aes256_ctr_proof(key, nonce, data.counter, plaintext, ciphertext)
				break
			default:
				throw new Error(`Unsupported algorithm: ${data.algorithm}`)
			}

			const result: ProveResult = JSON.parse(resultJson)
			if(result.error) {
				throw new Error(`Stwo proof generation failed: ${result.error}`)
			}

			if(!result.proof) {
				throw new Error('Stwo proof generation failed: no proof returned')
			}

			// Return proof as base64 string (stwo already returns it as base64)
			return { proof: result.proof }
		},

		async groth16Verify(publicSignals, proof, logger) {
			await ensureWasmInitialized(fetcher, logger)

			// proof is either string (base64) or Uint8Array
			const proofB64 = typeof proof === 'string'
				? proof
				: Base64.fromUint8Array(proof)

			let resultJson: string
			// Determine verification function based on algorithm
			if(algorithm === 'chacha20') {
				resultJson = stwo.verify_chacha20_proof(proofB64)
			} else {
				resultJson = stwo.verify_aes_ctr_proof(proofB64)
			}

			const result: VerifyResult = JSON.parse(resultJson)
			if(result.error) {
				logger?.warn({ error: result.error }, 'Stwo verification failed')
				return false
			}

			return result.valid === true
		},

		release() {
			// WASM module cannot be easily unloaded, but we can reset the init state
			// so it will be re-fetched on next use
			wasmInitialized = false
			initPromise = undefined
		}
	}
}
