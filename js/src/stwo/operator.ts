import { Base64 } from 'js-base64'
import type { EncryptionAlgorithm, MakeZKOperatorOpts, ZKOperator, ZKProofInput } from '../types.ts'
import { generate_aes128_ctr_proof, generate_aes256_ctr_proof, generate_chacha20_proof, initSync, verify_aes_ctr_proof, verify_chacha20_proof } from './s2circuits-wrapper.ts'

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

function assertU32Counter(counter: number): void {
	if(!Number.isInteger(counter) || counter < 0 || counter > 0xFFFFFFFF) {
		throw new RangeError('counter must be a uint32 integer (0 to 4294967295)')
	}
}

let wasmInitialized = false
let initPromise: Promise<void> | undefined

async function ensureWasmInitialized(): Promise<void> {
	if(wasmInitialized) {
		return
	}

	if(initPromise) {
		return initPromise
	}

	initPromise = (async() => {
		try {
			// Node.js target has WASM embedded in the .cjs file
			// initSync is a no-op that doesn't need the WASM bytes
			initSync()
			wasmInitialized = true
		} catch(err) {
			initPromise = undefined
			throw err
		}
	})()

	return initPromise
}

function serializeWitness(algorithm: EncryptionAlgorithm, input: ZKProofInput): Uint8Array {
	if(!input.noncesAndCounters?.length) {
		throw new Error('noncesAndCounters must be a non-empty array')
	}

	const { noncesAndCounters: [{ nonce, counter }] } = input
	assertU32Counter(counter)
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
}: MakeZKOperatorOpts<{}>): ZKOperator {
	return {
		generateWitness(input) {
			// Stwo combines witness generation and proving, so we just serialize
			// the input here to be used by groth16Prove
			return serializeWitness(algorithm, input)
		},

		async groth16Prove(witness) {
			await ensureWasmInitialized()
			const data = deserializeWitness(witness)

			const key = Base64.toUint8Array(data.key)
			const nonce = Base64.toUint8Array(data.nonce)
			const plaintext = Base64.toUint8Array(data.plaintext)
			const ciphertext = Base64.toUint8Array(data.ciphertext)

			let resultJson: string
			switch (data.algorithm) {
			case 'chacha20':
				resultJson = generate_chacha20_proof(key, nonce, data.counter, plaintext, ciphertext)
				break
			case 'aes-128-ctr':
				resultJson = generate_aes128_ctr_proof(key, nonce, data.counter, plaintext, ciphertext)
				break
			case 'aes-256-ctr':
				resultJson = generate_aes256_ctr_proof(key, nonce, data.counter, plaintext, ciphertext)
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

			// Return the STARK proof directly - public inputs are cryptographically
			// bound via Fiat-Shamir hashes inside the proof
			return { proof: result.proof }
		},

		async groth16Verify(publicSignals, proof, logger) {
			await ensureWasmInitialized()

			// Get verifier's expected public inputs
			const expectedNonce = publicSignals.noncesAndCounters[0]?.nonce
			const expectedCounter = publicSignals.noncesAndCounters[0]?.counter
			// Note: in JS library, 'in' is ciphertext, 'out' is plaintext
			const expectedCiphertext = publicSignals.in
			const expectedPlaintext = publicSignals.out

			if(!expectedNonce || expectedCounter === undefined) {
				logger?.warn('Invalid publicSignals: missing nonce or counter')
				return false
			}

			assertU32Counter(expectedCounter)

			// The proof is the raw base64-encoded STARK proof
			const proofStr = typeof proof === 'string'
				? proof
				: new TextDecoder().decode(proof)

			// Verify the STARK proof with verifier-supplied public inputs.
			// Security: Public inputs (nonce, counter, plaintext/ciphertext hashes) are
			// cryptographically bound to the proof via Fiat-Shamir transformation.
			// The WASM verify function recomputes the hashes from verifier's data and
			// compares with the proof's embedded hashes. If they don't match, or if
			// the STARK proof is invalid, verification fails.
			let resultJson: string
			if(algorithm === 'chacha20') {
				resultJson = verify_chacha20_proof(
					proofStr, expectedNonce, expectedCounter, expectedPlaintext, expectedCiphertext
				)
			} else {
				resultJson = verify_aes_ctr_proof(
					proofStr, expectedNonce, expectedCounter, expectedPlaintext, expectedCiphertext
				)
			}

			const result: VerifyResult = JSON.parse(resultJson)
			if(result.error) {
				logger?.warn({ error: result.error }, 'Stwo STARK verification failed')
				return false
			}

			return result.valid === true
		},

		release() {
			// WASM module cannot be easily unloaded, but we can reset the init state
			// so it will be re-fetched on next use.
			// Note: This affects all operator instances since wasmInitialized/initPromise
			// are module-level. This is intentional - the WASM module is shared.
			wasmInitialized = false
			initPromise = undefined
		}
	}
}
