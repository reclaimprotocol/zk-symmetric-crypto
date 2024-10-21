import {EncryptionAlgorithm, ZKOperator} from "./types";
import {join} from "path";
import {CONFIG} from "./config";
import {Base64, toBase64} from "js-base64";
import fs from "fs";
import {json} from "node:stream/consumers";

let koffi


let verify:(...args: any[]) => any
let free:(...args: any[]) => any
let prove:(...args: any[]) => any
let initAlgorithm:(...args: any[]) => any

let initDone = false

try {
	koffi = require('koffi');
	if(koffi?.version){
		koffi.reset() //otherwise tests will fail

		// define object GoSlice to map to:
		// C type struct { void *data; GoInt len; GoInt cap; }
		const GoSlice = koffi.struct('GoSlice', {
			data: 'void *',
			len:  'longlong',
			cap: 'longlong'
		})

		const ProveReturn = koffi.struct('ProveReturn', {
			r0: 'void *',
			r1:  'longlong',
		})


		const resFolder = `../resources/gnark`

		const arch = process.arch

		const libVerifyPath = join(
			__dirname,
			`${resFolder}/${arch}/libverify.so`
		)

		const libProvePath = join(
			__dirname,
			`${resFolder}/${arch}/libprove.so`
		)

		const libVerify = koffi.load(libVerifyPath)
		const libProve = koffi.load(libProvePath)

		verify = libVerify.func('Verify', 'unsigned char', [GoSlice])
		free = libProve.func('Free', 'void', ['void *'])
		prove = libProve.func('Prove', ProveReturn, [GoSlice])
		initAlgorithm = libProve.func('InitAlgorithm', 'unsigned char', ['unsigned char', GoSlice, GoSlice])
	}
} catch (e){
	koffi = undefined
	console.log("Gnark is only supported on linux x64 & ARM64.", e.toString())
}


async function initGnark(){
	const { join } = await import('path')

	const fs = require('fs')

	const folder = `../resources/gnark`

	function initAlg(id, name) {
		let keyPath = join(__dirname,`${folder}/pk.${name}`)
		let keyFile = fs.readFileSync(keyPath)

		let r1Path = join(__dirname,`${folder}/r1cs.${name}`)
		let r1File = fs.readFileSync(r1Path)

		let f1 = {
			data: Buffer.from(keyFile),
			len:keyFile.length,
			cap:keyFile.length
		}
		let f2 = {
			data: Buffer.from(r1File),
			len:r1File.length,
			cap:r1File.length
		}

		initAlgorithm(id,f1, f2)
	}

	initAlg(0, 'chacha20')
	initAlg(1, 'aes128')
	initAlg(2, 'aes256')
	initAlg(3, 'chacha20_oprf')

	initDone = true
}

export async function makeLocalGnarkZkOperator(cipher: EncryptionAlgorithm): Promise<ZKOperator> {

	if(koffi){

		return Promise.resolve({

			async generateWitness(input): Promise<Uint8Array> {
				return generateGnarkWitness(cipher, input)
			},

			//used in nodeJS only for tests
			async groth16Prove(witness: Uint8Array) {

				if (!initDone){
					await initGnark()
				}
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

			async groth16Verify(publicSignals, proof) {

				const {
					bitsToUint8Array
				} = CONFIG[cipher]


				const proofStr = proof['proofJson']

				const verifyParams = {
					cipher:cipher,
					proof: proofStr,
					publicSignals: Base64.fromUint8Array(bitsToUint8Array(publicSignals.flat())),
				}

				const paramsJson = JSON.stringify(verifyParams)
				const paramsBuf = strToUint8Array(paramsJson)

				const params = {
					data: paramsBuf,
					len:paramsJson.length,
					cap:paramsJson.length

				}

				return verify(params) === 1
			},

		})
	} else {
		return Promise.resolve({
			async generateWitness(input): Promise<Uint8Array> {
				return generateGnarkWitness(cipher, input)
			},

			async groth16Prove(witness) {
				throw new Error("not supported")
			},

			async groth16Verify(publicSignals, proof) {
				throw new Error("not supported")
			},

		})
	}
}

export function makeLocalGnarkOPRFOperator(){
	return {
		async generateWitness(input): Promise<Uint8Array> {
			const witness = {
				cipher: input.cipher,
				key: toBase64(input.key),
				nonce: toBase64(input.nonce),
				counter: input.counter,
				input: toBase64(input.input),
				oprf: input.oprf
			}
			const paramsJson = JSON.stringify(witness)
			return strToUint8Array(paramsJson)
		},

		async proveOPRF(witness: Uint8Array) {
			if (!initDone){
				await initGnark()
			}
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

		async verifyOPRF(input, proof) {


			const signals = {
				nonce: toBase64(input.nonce),
				counter: input.counter,
				input: toBase64(input.input),
				oprf: input.oprf
			}

			const strSignals = JSON.stringify(signals)
			const verifyParams = {
				cipher:'chacha20-oprf',
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

			return verify(params) === 1
		},
	}
}

function generateGnarkWitness(cipher:EncryptionAlgorithm, input){
	const {
		bitsToUint8Array,
		isLittleEndian
	} = CONFIG[cipher]


	//input is bits, we convert them back to bytes
	const proofParams = {
		cipher:cipher,
		key: Base64.fromUint8Array(bitsToUint8Array(input.key.flat())),
		nonce: Base64.fromUint8Array(bitsToUint8Array(input.nonce.flat())),
		counter: deSerialiseCounter(),
		input: Base64.fromUint8Array(bitsToUint8Array(input.in.flat())),
	}

	const paramsJson = JSON.stringify(proofParams)
	return strToUint8Array(paramsJson)


	function deSerialiseCounter() {
		const bytes = bitsToUint8Array(input.counter)
		const counterView = new DataView(bytes.buffer)
		return counterView.getUint32(0,isLittleEndian)
	}
}

function strToUint8Array(str: string) {
	return new TextEncoder().encode(str)
}


