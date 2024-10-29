import { describe, it } from 'node:test'
import { loadCircuit, toUint32Array, uintArray32ToBits } from './utils.ts'

describe('ChaCha Circuits Tests', () => {

	it('should add two 32bit numbers', async() => {
		const circuit = await loadCircuit('add32bits')

		const pairs = [
			{ a: 2, b: 5 }, // trivial
			{ a: 0, b: 0 }, // trivial
			{
				a: 0x11111111,
				b: 0x9b8d6f43
			},
			{
				// 32bit max - 1
				a: 0xffffffff - 1,
				b: 1
			},
			{
				// 32bit max - 1
				a: 0xffffffff - 1,
				b: 2
			},
			{
				a: 1365533105,
				b: 710897996
			}
		]

		for(const input of pairs) {
			const output = ((input.a + input.b) & 0xffffffff) >>> 0
			const outputBits = uintArray32ToBits([output])[0]
			const w = await circuit.calculateWitness(
				{
					a: uintArray32ToBits([input.a]),
					b: uintArray32ToBits([input.b])
				}
			)
			await circuit.checkConstraints(w)
			await circuit.assertOut(w, { out: outputBits })
		}
	})

	it('should XOR two 32bit numbers', async() => {
		const circuit = await loadCircuit('xor32bits')

		const pairs = [
			{ 
				a: 1,
				b: 5,
				out: 4
			},
			{
				a: 0x61707865,
				b: 0x3120646e,
				out: 0x50501c0b
			},
			{
				a: 0x01234567,
				b: 0x12131415,
				out: 0x13305172
			},
			{
				a: 2076431101,
				b: 0x3d631689,
				out: 1184941172
			},
			{
				a: 0xffffff0f,
				b: 0x0fffffff,
				out: 0xf00000f0
			}
		]

		for(const { a, b, out } of pairs) {
			const outBits = uintArray32ToBits([out])[0]
			const w = await circuit.calculateWitness({
				a: uintArray32ToBits([a])[0],
				b: uintArray32ToBits([b])[0]
			})
			await circuit.checkConstraints(w)
			await circuit.assertOut(w, {out: outBits})
		}
	})

	it('should rotate left 32bit number', async() => {
		const circuit = await loadCircuit('rotateLeft32bits')

		const inputs = [
			1234, // trivial case
			0x0fffffff - 1,
			0x0fffffff,
			0xffffffff,
			0x51721330,
			2643868144,
			1184941172,
			0x13305172,
			1039408964
		]

		for(const input of inputs) {
			const outputs = [
				rotateLeft32bits(input, 16),
				rotateLeft32bits(input, 12),
				rotateLeft32bits(input, 8),
				rotateLeft32bits(input, 7),
			]
			const w = await circuit.calculateWitness({
				in: uintArray32ToBits([input])[0]
			})

			await circuit.checkConstraints(w)
			await circuit.assertOut(w, {
				out: uintArray32ToBits(outputs)
			})
		}
	})

	// chacha test vectors from: https://datatracker.ietf.org/doc/html/draft-nir-cfrg-chacha20-poly1305#section-2.1.1
	it('should perform a chacha20 quarter round', async() => {
		const circuit = await loadCircuit('chacha20qr')

		const pairs = [
			{
				input: [
					0x11111111, 0x01020304,
					0x9b8d6f43, 0x01234567,
				],
				output: [
					0xea2a92f4, 0xcb1cf8ce,
					0x4581472e, 0x5881c4bb,
				]
			},
			{
				input: [
					0x516461b1, 0x2a5f714c,
					0x53372767, 0x3d631689
				],
				output: [
					0xbdb886dc, 0xcfacafd2,
					0xe46bea80, 0xccc07c79
				]
			},
		]

		for(const { input, output } of pairs) {
			const w = await circuit.calculateWitness({
				in: uintArray32ToBits(input)
			})
					
			await circuit.checkConstraints(w)
			await circuit.assertOut(w, {
				out: uintArray32ToBits(output)
			})
		}
	})

	it('should execute a chacha round', async() => {
		const circuit = await loadCircuit('chacha20round')

		const pairs = [
			{
				input: [
					0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
					0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
					0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
					0x00000001, 0x09000000, 0x4a000000, 0x00000000,
				],
				output: [
					0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
					0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
					0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
					0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
				]
			}
		]

		for(const { input, output } of pairs) {
			const w = await circuit.calculateWitness({
				in: uintArray32ToBits(input)
			})
			await circuit.checkConstraints(w)

			await circuit.assertOut(w, {
				out: uintArray32ToBits(output)
			})
		}
	})

	it('should encrypt a chacha20 block', async() => {
		const circuit = await loadCircuit('chacha20')

		const vectors = [
			{
				keyBytes: Buffer.from(
					[
						0x00, 0x01, 0x02, 0x03,
						0x04, 0x05, 0x06, 0x07,
						0x08, 0x09, 0x0a, 0x0b,
						0x0c, 0x0d, 0x0e, 0x0f,
						0x10, 0x11, 0x12, 0x13,
						0x14, 0x15, 0x16, 0x17,
						0x18, 0x19, 0x1a, 0x1b,
						0x1c, 0x1d, 0x1e, 0x1f
					]
				),
				nonceBytes: Buffer.from(
					[
						0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x4a,
						0x00, 0x00, 0x00, 0x00
					]
				),
				counter: 1,
				plaintextBytes: Buffer.from(
					[
						0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
						0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
						0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
						0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
					]
				),
				ciphertextBytes: Buffer.from(
					[
						0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
						0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
						0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
						0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8
					]
				)
			}
		]

		for(const { keyBytes, nonceBytes, counter, plaintextBytes, ciphertextBytes } of vectors) {			
			const ciphertextBits = uintArray32ToBits(toUint32Array(ciphertextBytes))
			const plaintextBits = uintArray32ToBits(toUint32Array(plaintextBytes))
			const counterBits = uintArray32ToBits([counter])[0]
			const w = await circuit.calculateWitness({
				key: uintArray32ToBits(toUint32Array(keyBytes)),
				nonce: uintArray32ToBits(toUint32Array(nonceBytes)),
				counter: counterBits,
				in: plaintextBits,
			})
			
			await circuit.checkConstraints(w)
			await circuit.assertOut(w, {
				out: ciphertextBits
			})

			// check decryption
			const w2 = await circuit.calculateWitness({
				key: uintArray32ToBits(toUint32Array(keyBytes)),
				nonce: uintArray32ToBits(toUint32Array(nonceBytes)),
				counter: counterBits,
				in: ciphertextBits,
			})
			
			await circuit.checkConstraints(w2)
			await circuit.assertOut(w2, { out: plaintextBits })
		}
	})

	function rotl32(v, c) {
        return (v << c) | (v >>> (32 - c));
    }

    function chacha20_round(x, a, b, c, d) {
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

		x[a] = x[a] >>> 0
		x[b] = x[b] >>> 0
		x[c] = x[c] >>> 0
		x[d] = x[d] >>> 0

		return x
    }

	function rotateLeft32bits(a: number, b: number) {
		const bits = numToBitsNumerical(a)
		for(let i = 0;i < b;i++) {
			bits.push(bits.shift()!)
		}

		return bitsToNum(bits)
	}

	function xorNums(a: number, b: number) {
		const bits = numToBitsNumerical(a)
		const bits2 = numToBitsNumerical(b)
		for(let i = 0;i < bits.length;i++) {
			bits[i] ^= bits2[i]
		}

		return bitsToNum(bits)
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

	function add32Bits(a: number, b: number) {
		const bits = numToBitsNumerical(a)
		const bits2 = numToBitsNumerical(b)
		for(let i = 0;i < bits.length;i++) {
			bits[i] += bits2[i]
		}

		return bitsToNum(bits)
	}

	function numToBits(num: number, bitCount = 32) {
		return (num >>> 0).toString(2)
	}

	function bitsToNum(bits: number[]) {
		let num = 0

		let exp = 2 ** (bits.length - 1)
		for(let i = 0;i < bits.length;i++) {
			num += bits[i] * exp
			exp /= 2
		}

		return num
	}
})