import { fromUint8Array, toUint8Array } from 'js-base64'
import * as koffi from 'koffi'
import { Logger } from '../types'
import { KeygenResult, KeyShare, OPRFRequestData, OPRFResponseData, TOPRFResponseData } from './types'
import { GnarkLib, loadGnarkLib, strToUint8Array } from './utils'


export function makeLocalGnarkTOPRFOperator(fetcher) {
	let initDone = false
	let gLib: GnarkLib
	return {
		async GenerateThresholdKeys(total: number, threshold: number, logger?: Logger): Promise<KeygenResult> {
			const lib = await initGnark(logger)
			const { generateThresholdKeys, vfree } = lib

			const params = {
				total: total,
				threshold: threshold,
			}

			const pamamsJson = strToUint8Array(JSON.stringify(params))
			const bParams = {
				data: Buffer.from(pamamsJson),
				len:pamamsJson.length,
				cap:pamamsJson.length
			}
			const res = generateThresholdKeys(bParams)
			const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString()
			vfree(res.r0) // Avoid memory leak!
			const parsed = JSON.parse(resJson)

			const shares: KeyShare[] = []
			for(let i = 0; i < parsed.shares.length; i++) {
				const share = parsed.shares[i]
				shares.push({
					index:share.index,
					publicKey: toUint8Array(share.publicKey),
					privateKey: toUint8Array(share.privateKey),
				})
			}

			return Promise.resolve({
				publicKey: toUint8Array(parsed.publicKey),
				privateKey: toUint8Array(parsed.privateKey),
				shares: shares,
			})
		},

		async generateOPRFRequestData(data, domainSeparator: string, logger?: Logger): Promise<OPRFRequestData> {
			const lib = await initGnark(logger)
			const { generateOPRFRequest, free } = lib

			const params = {
				data: data,
				domainSeparator: domainSeparator,
			}

			const pamamsJson = strToUint8Array(JSON.stringify(params))
			const wtns = {
				data: Buffer.from(pamamsJson),
				len:pamamsJson.length,
				cap:pamamsJson.length
			}
			const res = generateOPRFRequest(wtns)
			const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString()
			free(res.r0) // Avoid memory leak!
			const parsed = JSON.parse(resJson)
			return Promise.resolve({
				mask: toUint8Array(parsed.mask),
				maskedData: toUint8Array(parsed.maskedData),
				secretElements: [toUint8Array(parsed.secretElements[0]), toUint8Array(parsed.secretElements[1])]
			})
		},

		async TOPRFFinalize(serverPublicKey: Uint8Array, request: OPRFRequestData, responses: TOPRFResponseData[], logger?: Logger): Promise<Uint8Array> {

			const lib = await initGnark(logger)
			const { toprfFinalize, free } = lib

			const resps: any[] = []
			for(const { index, publicKeyShare, evaluated, c, r } of responses) {
				const resp = {
					index: index,
					publicKeyShare: fromUint8Array(publicKeyShare),
					evaluated: fromUint8Array(evaluated),
					c: fromUint8Array(c),
					r: fromUint8Array(r),
				}
				resps.push(resp)
			}

			const params = {
				serverPublicKey: fromUint8Array(serverPublicKey),
				request: {
					mask: fromUint8Array(request.mask),
					maskedData: fromUint8Array(request.maskedData),
					secretElements: [fromUint8Array(request.secretElements[0]), fromUint8Array(request.secretElements[1])]
				},
				responses: resps
			}

			const pamamsJson = strToUint8Array(JSON.stringify(params))
			const libReq = {
				data: Buffer.from(pamamsJson),
				len:pamamsJson.length,
				cap:pamamsJson.length
			}
			const res = toprfFinalize(libReq)
			const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString()
			free(res.r0) // Avoid memory leak!
			const parsed = JSON.parse(resJson)
			return Promise.resolve(toUint8Array(parsed.output))
		},

		async OPRFEvaluate(serverPrivate: Uint8Array, maskedData: Uint8Array, logger?: Logger): Promise<OPRFResponseData> {
			const lib = await initGnark(logger)
			const { oprfEvaluate, vfree } = lib
			const params = {
				serverPrivate: fromUint8Array(serverPrivate),
				maskedData: fromUint8Array(maskedData),
			}

			const pamamsJson = strToUint8Array(JSON.stringify(params))
			const libParams = {
				data: Buffer.from(pamamsJson),
				len:pamamsJson.length,
				cap:pamamsJson.length
			}
			const res = oprfEvaluate(libParams)
			const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString()
			vfree(res.r0) // Avoid memory leak!
			const parsed = JSON.parse(resJson)
			return Promise.resolve({
				evaluated: toUint8Array(parsed.evaluated),
				c: toUint8Array(parsed.c),
				r: toUint8Array(parsed.r),
			})
		},
	}

	async function initGnark(logger?: Logger) {
		gLib ||= await loadGnarkLib()
		if(initDone) {
			return gLib
		}

		const ext = 'chacha20_oprf'
		const id = 3
		const [pk, r1cs] = await Promise.all([
			fetcher.fetch('gnark', `pk.${ext}`, logger),
			fetcher.fetch('gnark', `r1cs.${ext}`, logger),
		])

		const f1 = { data: pk, len: pk.length, cap: pk.length }
		const f2 = { data: r1cs, len: r1cs.length, cap: r1cs.length }

		await gLib.initAlgorithm(id, f1, f2)

		initDone = true

		return gLib
	}
}


