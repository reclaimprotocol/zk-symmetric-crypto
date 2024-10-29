import * as snarkjs from "snarkjs"
import { PrivateInput, Proof, PublicInput, VerificationKey } from "./types"
import { bitsToUint8Array } from "../utils";


const CIRCUIT_WASM_PATH = "./resources/aes/circuit.wasm"

export async function generateProof(
	{
		key,
		iv,
	}: PrivateInput,
	{
		ciphertext,
		//redactedPlaintext,
	}: PublicInput,
	zkey
): Promise<Proof> {

	//convert to bit arrays
	const encKey = buffer2bits(Buffer.from(key));
	const ivCounter = buffer2bits(Buffer.from(iv));
	const ct = buffer2bits(Buffer.from(ciphertext));

	const { proof, publicSignals } = await snarkjs.groth16.fullProve(
		{
			encKey:encKey,
			iv:ivCounter,
			ciphertext:ct,
		},
		CIRCUIT_WASM_PATH,
		zkey.data
	)

	return {
		proofJson: JSON.stringify(proof),
		plaintext: bitsToUint8Array(
			publicSignals
				.slice(0, ct.length * 8)
		)
	}
}

export async function verifyProof(
	{ proofJson }: Proof,
	publicInput: PublicInput,
	zkey: VerificationKey
): Promise<boolean> {
	if(!zkey.json) {
		zkey.json = await snarkjs.zKey.exportVerificationKey(zkey.data)
	}

	const pubInputs = getSerialisedPublicInputs(publicInput)
	return await snarkjs.groth16.verify(
		zkey.json,
		pubInputs,
		JSON.parse(proofJson)
	)
}

/**
 * Serialise public inputs to array of numbers for the ZK circuit
 * the format is spread (output, ciphertext, redactedPlaintext)
 * @param inp 
 */
function getSerialisedPublicInputs(inp: PublicInput) {
	return [
		...Array.from(buffer2bits(Buffer.from(inp.ciphertext))),
	]
}

function buffer2bits(buff:Buffer) {
	const res:number[] = [];
	for (let i = 0; i < buff.length; i++) {
		for (let j = 0; j < 8; j++) {
			if ((buff[i] >> 7-j) & 1) {
				res.push(1);
			} else {
				res.push(0);
			}
		}
	}
	return res;
}