import {encryptData} from "./utils";
import {Base64, fromBase64} from "js-base64";

import {createHash} from "node:crypto";
import {makeLocalGnarkOPRFOperator} from "../gnark/toprf";
import {makeLocalFileFetch} from "../file-fetch";

describe('OPRF circuits Tests', () => {

    it('should prove OPRF', async() => {
        const fetcher = makeLocalFileFetch()
        const operator = makeLocalGnarkOPRFOperator(fetcher)

        const serverPrivate = 'A3q7HrA+10FUiL0Q9lrDBRdRuoq752oREn9STszgLEo='
        const serverPublic =  'dGEZEZY4qexS2WyOL8KDcv99BWjL7ivaKvvarCcbYCU='

        const email = "test@email.com"
        const domainSeparator = "reclaim"

        const req =  await operator.generateOPRFRequestData(email, domainSeparator)
        const resp = await operator.OPRF(serverPrivate, req.maskedData)
        const result = await operator.processOPRFResponse(serverPublic, req.mask, req.maskedData, resp.response, resp.c, resp.s)


        expect(result.output).toEqual('T3ikGmkt+a/uou6kEz97AmuFGECsTSNINmN4dWcaiaU=')

        const rawOutput = fromBase64(result.output)
        const hash = createHash('sha256');
        hash.update(rawOutput)
        const nullifier = hash.digest('hex')
        expect(nullifier).toEqual('3555badf313bc299351e007040b8797ab7f1d75b1954b801cd8e3b9dc3531104') // ACTUAL "NULLIFIER" value

        const pos = 10
        const len = email.length


        // response from OPRF server + local values
        // pre-calculated for email & separator above
        const oprf = {
            pos: pos, //pos in plaintext
            len: len, // length of data to "hash"
            domainSeparator: Base64.fromUint8Array(new Uint8Array(Buffer.from(domainSeparator))),

            serverPublicKey: serverPublic,

            // values from OPRF procedure
            mask: req.mask,
            serverResponse: resp.response,
            output: result.output, // => hashing this produces that "oprf hash" or nullifier that we need
            // DLEQ proof
            c: resp.c,
            s:  resp.s
        }


        const plaintext = new Uint8Array(Buffer.alloc(128)) //2 blocks
        plaintext.set(new Uint8Array(Buffer.from(email)), pos) //replace part of plaintext with email

        const key = new Uint8Array(Array.from(Array(32).keys()))
        const iv = new Uint8Array(Array.from(Array(12).keys()))

        const ciphertext = encryptData(
            'chacha20',
            plaintext,
            key,
            iv
        )

        const witnessParams = {
            "cipher": "chacha20-oprf",
            "key": key,
            "nonce": iv,
            "counter": 1,
            "input": ciphertext, // plaintext will be calculated in library
            "oprf": oprf
        }


        const wtns = await operator.generateWitness(witnessParams)

        const proof = await operator.proveOPRF(wtns)

        const verifySignals = {
            "nonce": iv,
            "counter": 1,
            "input": ciphertext,
            "oprf": {
                pos: pos, //pos in plaintext
                len: len, // length of data to "hash"
                domainSeparator: oprf.domainSeparator,
                serverPublicKey: oprf.serverPublicKey, // set externally by client when proving & attestor when verifying
                // output from OPRF procedure which corresponds to
                serverResponse: oprf.serverResponse,
                output: oprf.output,
                // DLEQ proof
                c: oprf.c,
                s: oprf.s,
            }
        }

        expect(await operator.verifyOPRF(verifySignals, proof)).toEqual(true)
    })
})