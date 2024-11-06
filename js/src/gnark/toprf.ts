import {Base64, toBase64} from "js-base64";
import * as koffi from "koffi";
import {Logger} from "../types";
import {GnarkLib, loadGnarkLib, strToUint8Array} from "./utils";



export function makeLocalGnarkOPRFOperator(fetcher){
    let initDone = false
    let gLib:GnarkLib
    return {
        async generateWitness(input): Promise<Uint8Array> {
            const witness = {
                cipher: input.cipher,
                key: toBase64(input.key),
                nonce: toBase64(input.nonce),
                counter: input.counter,
                input: toBase64(input.input),
                toprf: input.toprf
            }
            const paramsJson = JSON.stringify(witness)
            return strToUint8Array(paramsJson)
        },

        async proveOPRF(witness: Uint8Array, logger?: Logger) {
            const lib = await initGnark(logger)

            const {prove, free} = lib
            const wtns = {
                data: Buffer.from(witness),
                len:witness.length,
                cap:witness.length
            }
            const res = prove(wtns)
            const resJson = Buffer.from(koffi.decode(res.r0, 'unsigned char', res.r1)).toString()
            free(res.r0) // Avoid memory leak!
            const proof = JSON.parse(resJson)
            return Promise.resolve(proof)
        },

        async verifyOPRF(input, proof, logger?: Logger) {
            const lib = await initGnark(logger)
            const signals = {
                nonce: toBase64(input.nonce),
                counter: input.counter,
                input: toBase64(input.input),
                toprf: input.toprf
            }

            const strSignals = JSON.stringify(signals)
            const verifyParams = {
                cipher:'chacha20-toprf',
                proof: proof.proof.proofJson,
                publicSignals: toBase64(strSignals),
            }

            const paramsJson = JSON.stringify(verifyParams)
            const paramsBuf = strToUint8Array(paramsJson)

            const params = {
                data: paramsBuf,
                len:paramsJson.length,
                cap:paramsJson.length

            }

            return lib.verify(params) === 1
        },

        async GenerateThresholdKeys(total, threshold, logger?: Logger) {
            const lib = await initGnark(logger)
            const {generateThresholdKeys, vfree} = lib

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
            const req = JSON.parse(resJson)
            return Promise.resolve(req)
        },

        async generateOPRFRequestData(data, domainSeparator: string, logger?: Logger) {
            const lib = await initGnark(logger)
            const {generateOPRFRequest, free} = lib

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
            const req = JSON.parse(resJson)
            return Promise.resolve(req)
        },

        async TOPRFFinalize(serverPublicKey, request, responses, logger?: Logger) {

            const lib = await initGnark(logger)
            const {toprfFinalize, free} = lib
            const params = {
                serverPublicKey: serverPublicKey,
                request: request,
                responses: responses
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
            const req = JSON.parse(resJson)
            return Promise.resolve(req)
        },

        async OPRFEvaluate(serverPrivate, maskedData:string, logger?: Logger) {
            const lib = await initGnark(logger)
            const {oprfEvaluate, vfree} = lib
            const params = {
                serverPrivate: serverPrivate,
                maskedData: maskedData,
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
            const req = JSON.parse(resJson)
            return Promise.resolve(req)
        },
    }

    async function initGnark(logger?: Logger) {
        gLib ||= await loadGnarkLib()
        if(initDone) {
            return gLib
        }

        const  ext  = 'chacha20_oprf'
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




