import type { FileFetch, KeyShare, Logger, OPRFOperator, OPRFRequestData, OPRFResponseData } from '../types.ts'
import {
	get_toprf_info,
	toprf_create_request,
	toprf_evaluate,
	toprf_finalize,
	toprf_generate_keys
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
}

/**
 * Create a stwo OPRF operator with gnark-compatible MiMC hash.
 *
 * This operator uses the same hash function (MiMC over BN254) as gnark,
 * so outputs are compatible between the two systems.
 */
export function makeStwoOPRFOperator({
	fetcher,
}: MakeStwoOPRFOperatorOpts): OPRFOperator {
	return {
		async generateWitness(_input) {
			// Stwo combines witness generation and proving
			// For OPRF, we don't need a separate witness step
			throw new Error('generateWitness not supported for stwo OPRF - use groth16Prove directly')
		},

		async groth16Prove(_witness, _logger) {
			// STARK proof generation for cipher + TOPRF would go here
			// For now, we only support the TOPRF operations (no ZK proof yet)
			throw new Error('groth16Prove not yet implemented for stwo OPRF')
		},

		async groth16Verify(_publicSignals, _proof, _logger) {
			throw new Error('groth16Verify not yet implemented for stwo OPRF')
		},

		async generateThresholdKeys(total, threshold, logger) {
			await ensureWasmInitialized(fetcher, logger)

			// Use current time as seed for randomness
			const seed = BigInt(Date.now()) * BigInt(1000000) + BigInt(Math.floor(Math.random() * 1000000))

			const resultJson = toprf_generate_keys(total, threshold, seed)
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
