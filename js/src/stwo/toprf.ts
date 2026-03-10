import type { EncryptionAlgorithm, FileFetch, KeyShare, Logger, OPRFOperator, ZKProofInputOPRF } from '../types.ts'
import {
	generate_cipher_toprf_proof,
	get_toprf_info,
	toprf_create_request,
	toprf_evaluate,
	toprf_finalize,
	toprf_generate_keys,
	verify_cipher_toprf_proof
} from './s2circuits-wrapper.ts'

// Node.js target auto-initializes WASM at import time, so no explicit init needed
// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function ensureWasmInitialized(_fetcher: FileFetch, _logger?: Logger): Promise<void> {
	// WASM is automatically loaded by the nodejs-target s2circuits.js
	return
}

type StwoKeysResult = {
	serverPublicKey: string
	shares: Array<{
		index: number
		privateKey: string
		publicKey: string
	}>
	error?: string
}

type StwoRequestResult = {
	mask: string
	maskedData: string
	secretElements: [string, string]
	error?: string
}

type StwoEvalResult = {
	evaluated: string
	c: string
	r: string
	publicKeyShare: string
	index: number
	error?: string
}

type StwoFinalizeResult = {
	output: string
	outputDecimal: string
	error?: string
}

type StwoProofResult = {
	success: boolean
	algorithm: string
	proof: string
	error?: string
}

type StwoVerifyResult = {
	valid: boolean
	algorithm?: string
	error?: string
}

function hexToUint8Array(hex: string): Uint8Array {
	if(hex.startsWith('0x')) {
		hex = hex.slice(2)
	}

	// Pad to even length
	if(hex.length % 2 !== 0) {
		hex = '0' + hex
	}

	const bytes = new Uint8Array(hex.length / 2)
	for(let i = 0; i < bytes.length; i++) {
		bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
	}

	return bytes
}

function uint8ArrayToHex(arr: Uint8Array): string {
	return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('')
}

export interface MakeStwoOPRFOperatorOpts {
	fetcher: FileFetch
	algorithm: EncryptionAlgorithm
}

/**
 * Serialize ZKProofInputOPRF to a witness buffer that can be passed to groth16Prove.
 * This format is compatible with stwo's combined cipher+TOPRF proof API.
 */
function serializeStwoWitness(algorithm: EncryptionAlgorithm, input: ZKProofInputOPRF): Uint8Array {
	// Build a JSON structure containing all inputs needed for prove
	const witnessData = {
		algorithm,
		key: uint8ArrayToHex(input.key),
		noncesAndCounters: input.noncesAndCounters.map(nc => ({
			nonce: uint8ArrayToHex(nc.nonce),
			counter: nc.counter,
		})),
		plaintext: uint8ArrayToHex(input.out),
		ciphertext: uint8ArrayToHex(input.in),
		toprf: {
			locations: input.toprf.locations,
			domainSeparator: input.toprf.domainSeparator,
			output: uint8ArrayToHex(input.toprf.output),
			responses: input.toprf.responses.map(resp => ({
				publicKeyShare: uint8ArrayToHex(resp.publicKeyShare),
				evaluated: uint8ArrayToHex(resp.evaluated),
				c: uint8ArrayToHex(resp.c),
				r: uint8ArrayToHex(resp.r),
			})),
			mask: uint8ArrayToHex(input.mask),
		},
	}

	return new TextEncoder().encode(JSON.stringify(witnessData))
}

/**
 * Deserialize witness back to components for proof generation.
 */
function deserializeStwoWitness(witness: Uint8Array): {
	algorithm: EncryptionAlgorithm
	key: Uint8Array
	nonce: Uint8Array
	counter: number
	plaintext: Uint8Array
	ciphertext: Uint8Array
	toprfJson: string
} {
	const text = new TextDecoder().decode(witness)
	const data = JSON.parse(text)

	// Get first nonce/counter (for now we support single block)
	const nc = data.noncesAndCounters[0]

	// Build TOPRF JSON in the format expected by generate_cipher_toprf_proof
	const toprfJson = JSON.stringify({
		locations: data.toprf.locations,
		domainSeparator: data.toprf.domainSeparator,
		output: '0x' + data.toprf.output,
		responses: data.toprf.responses.map((resp: {
			publicKeyShare: string
			evaluated: string
			c: string
			r: string
		}) => ({
			publicKeyShare: '0x' + resp.publicKeyShare,
			evaluated: '0x' + resp.evaluated,
			c: '0x' + resp.c,
			r: '0x' + resp.r,
		})),
		mask: '0x' + data.toprf.mask,
	})

	return {
		algorithm: data.algorithm,
		key: hexToUint8Array(data.key),
		nonce: hexToUint8Array(nc.nonce),
		counter: nc.counter,
		plaintext: hexToUint8Array(data.plaintext),
		ciphertext: hexToUint8Array(data.ciphertext),
		toprfJson,
	}
}

/**
 * Create a stwo OPRF operator with gnark-compatible MiMC hash.
 *
 * This operator uses the same hash function (MiMC over BN254) as gnark,
 * so outputs are compatible between the two systems.
 */
export function makeStwoOPRFOperator({
	fetcher,
	algorithm,
}: MakeStwoOPRFOperatorOpts): OPRFOperator {
	return {
		async generateWitness(input, logger) {
			await ensureWasmInitialized(fetcher, logger)
			// Serialize the input to a witness buffer
			return serializeStwoWitness(algorithm, input)
		},

		async groth16Prove(witness, logger) {
			await ensureWasmInitialized(fetcher, logger)

			// Deserialize witness to get components
			const data = deserializeStwoWitness(witness)

			// Call WASM to generate proof
			const resultJson = generate_cipher_toprf_proof(
				data.algorithm,
				data.key,
				data.nonce,
				data.counter,
				data.plaintext,
				data.ciphertext,
				data.toprfJson,
			)

			const result: StwoProofResult = JSON.parse(resultJson)

			if(result.error || !result.success) {
				throw new Error(`Proof generation failed: ${result.error || 'unknown error'}`)
			}

			// Return proof as Uint8Array (base64 decoded)
			return { proof: result.proof }
		},

		async groth16Verify(publicSignals, proof, logger) {
			await ensureWasmInitialized(fetcher, logger)

			// Get first nonce/counter
			const nc = publicSignals.noncesAndCounters[0]

			// Build TOPRF JSON for verification (no mask needed)
			const toprfJson = JSON.stringify({
				locations: publicSignals.toprf.locations,
				domainSeparator: publicSignals.toprf.domainSeparator,
				output: '0x' + uint8ArrayToHex(publicSignals.toprf.output),
				responses: publicSignals.toprf.responses.map(resp => ({
					publicKeyShare: '0x' + uint8ArrayToHex(resp.publicKeyShare),
					evaluated: '0x' + uint8ArrayToHex(resp.evaluated),
					c: '0x' + uint8ArrayToHex(resp.c),
					r: '0x' + uint8ArrayToHex(resp.r),
				})),
				mask: '0x00', // Not needed for verify, but required by parser
			})

			// Get proof string (either already string or convert from Uint8Array)
			const proofStr = typeof proof === 'string'
				? proof
				: new TextDecoder().decode(proof)

			// Call WASM to verify proof
			const resultJson = verify_cipher_toprf_proof(
				algorithm,
				proofStr,
				nc.nonce,
				nc.counter,
				publicSignals.out, // plaintext
				publicSignals.in, // ciphertext
				toprfJson,
			)

			const result: StwoVerifyResult = JSON.parse(resultJson)

			return result.valid === true
		},

		async generateThresholdKeys(total, threshold, logger) {
			await ensureWasmInitialized(fetcher, logger)

			// Randomness is handled internally by WASM using getrandom (CSPRNG)
			const resultJson = toprf_generate_keys(total, threshold)
			const result: StwoKeysResult = JSON.parse(resultJson)

			if(result.error) {
				throw new Error(`Key generation failed: ${result.error}`)
			}

			const shares: KeyShare[] = result.shares.map(share => ({
				index: share.index,
				publicKey: hexToUint8Array(share.publicKey),
				privateKey: hexToUint8Array(share.privateKey),
			}))

			return {
				publicKey: hexToUint8Array(result.serverPublicKey),
				privateKey: new Uint8Array(0), // Server private key not exposed in stwo
				shares,
			}
		},

		async generateOPRFRequestData(data, domainSeparator, logger) {
			await ensureWasmInitialized(fetcher, logger)

			const resultJson = toprf_create_request(data, domainSeparator)
			const result: StwoRequestResult = JSON.parse(resultJson)

			if(result.error) {
				throw new Error(`Request creation failed: ${result.error}`)
			}

			return {
				mask: hexToUint8Array(result.mask),
				maskedData: hexToUint8Array(result.maskedData),
				secretElements: [
					hexToUint8Array(result.secretElements[0]),
					hexToUint8Array(result.secretElements[1]),
				],
			}
		},

		async evaluateOPRF(serverPrivate, maskedData, logger) {
			await ensureWasmInitialized(fetcher, logger)

			// For stwo, we need to pass the full share info
			// The serverPrivate should include the share JSON
			// For now, we construct a minimal share object
			const privateKeyHex = uint8ArrayToHex(serverPrivate)

			// Note: stwo's toprf_evaluate expects the full share JSON
			// This is a compatibility layer - in practice, you'd store the full share
			const shareJson = JSON.stringify({
				index: 1, // Default index - should be passed separately
				privateKey: privateKeyHex,
				publicKey: '', // Will be computed from private key
			})

			const maskedDataHex = uint8ArrayToHex(maskedData)
			const resultJson = toprf_evaluate(shareJson, maskedDataHex)
			const result: StwoEvalResult = JSON.parse(resultJson)

			if(result.error) {
				throw new Error(`OPRF evaluation failed: ${result.error}`)
			}

			return {
				evaluated: hexToUint8Array(result.evaluated),
				c: hexToUint8Array(result.c),
				r: hexToUint8Array(result.r),
			}
		},

		async finaliseOPRF(serverPublicKey, request, responses, logger) {
			await ensureWasmInitialized(fetcher, logger)

			const params = {
				serverPublicKey: uint8ArrayToHex(serverPublicKey),
				request: {
					mask: uint8ArrayToHex(request.mask),
					maskedData: uint8ArrayToHex(request.maskedData),
					secretElements: [
						uint8ArrayToHex(request.secretElements[0]),
						uint8ArrayToHex(request.secretElements[1]),
					],
				},
				responses: responses.map((resp, i) => ({
					index: i + 1, // 1-indexed
					publicKeyShare: uint8ArrayToHex(resp.publicKeyShare),
					evaluated: uint8ArrayToHex(resp.evaluated),
					c: uint8ArrayToHex(resp.c),
					r: uint8ArrayToHex(resp.r),
				})),
			}

			const resultJson = toprf_finalize(JSON.stringify(params))
			const result: StwoFinalizeResult = JSON.parse(resultJson)

			if(result.error) {
				throw new Error(`TOPRF finalization failed: ${result.error}`)
			}

			// Output is a 256-bit (32 byte) MiMC hash
			return hexToUint8Array(result.output)
		},
	}
}

/**
 * Get stwo TOPRF circuit information.
 */
export async function getStwoTOPRFInfo(fetcher: FileFetch, logger?: Logger): Promise<object> {
	await ensureWasmInitialized(fetcher, logger)
	return JSON.parse(get_toprf_info())
}
