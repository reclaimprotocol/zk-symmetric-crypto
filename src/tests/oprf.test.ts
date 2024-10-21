import {randomBytes} from "crypto";
import {PrivateInput} from "../types";
import {encryptData} from "./utils";
import {Base64} from "js-base64";
import {makeLocalGnarkOPRFOperator} from "../gnark";

describe('OPRF circuits Tests', () => {

    it('should prove OPRF', async() => {

        const email = "test@email.com"
        const domainSeparator = "reclaim"
        const pos = 10
        const len = email.length


        // response from OPRF server + local values
        // pre-calculated for email & separator above
        const oprf = {
                pos: pos, //pos in plaintext
                len: len, // length of data to "hash"
                domainSeparator: Base64.fromUint8Array(new Uint8Array(Buffer.from(domainSeparator))),

                serverPublicKey: "vxLn+WUuKIsgBZbe/oRDuUXwUgHJiwalF0BjxpLMnSw=", // set externally by client when proving & attestor when verifying

                // values from OPRF procedure
                mask: "Bd7l0FC43Se7WWsMVlG5sTlb9u7RjLaQty7c04scOQI=",
                serverResponse: "iVGq7kFnuUDH4nBx7LYhBBGQcxDadJN/7z/XWj2sAww=",
                output: "eOv2n1nsmLuyxb7UgZlarKcq6gnKfJVMp9jadT42tRc=", // => hashing this produces that "oprf hash" or nullifier that we need
                // DLEQ proof
                c: "AgsIlrbNvWc9KL7YZoMw4lPPmkIkIXjP24JRvnqOUZQ=",
                s: "Ab7SzWnISNbA0eKhIIG8p9Q/3SOl4b7sDvRcJmwJfAQ="
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

        const operator = makeLocalGnarkOPRFOperator()
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