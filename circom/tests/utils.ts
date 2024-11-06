import { wasm as WasmTester } from 'circom_tester'
import { resolve, } from "path"

export function loadCircuit(name: string) {
	return WasmTester(resolve(`./circuits/tests/${name}.circom`))
}

/**
 * Converts a Uint8Array to an array of bits.
 * BE order.
 */
export function uint8ArrayToBitsBE(buff: Uint8Array | number[]) {
	const res: number[] = []
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

export function toUint32Array(buf: Uint8Array) {
	const arr = new Uint32Array(buf.length / 4)
	const arrView = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
	for(let i = 0;i < arr.length;i++) {
		arr[i] = arrView.getUint32(i * 4, true)
	}
	return arr
}

/**
 * Converts a Uint32Array to an array of bits.
 * LE order.
 */
export function uintArray32ToBits(uintArray: Uint32Array | number[]) {
	const bits: number[][] = []
	for (let i = 0; i < uintArray.length; i++) {
		const uint = uintArray[i]
		bits.push(numToBitsNumerical(uint))
	}

	return bits
}

function numToBitsNumerical(num: number, bitCount = 32) {
	const bits: number[] = []
	for(let i = 2 ** (bitCount - 1);i >= 1;i /= 2) {
		const bit = num >= i ? 1 : 0
		bits.push(bit)
		num -= bit * i
	}

	return bits
}