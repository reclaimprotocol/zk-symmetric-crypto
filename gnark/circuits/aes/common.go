package aes

import "github.com/consensys/gnark/frontend"

type AESWrapper struct {
	Key        []frontend.Variable
	Nonce      [12]frontend.Variable
	Counter    frontend.Variable
	Plaintext  [BLOCKS * 16]frontend.Variable `gnark:",public"`
	Ciphertext [BLOCKS * 16]frontend.Variable `gnark:",public"`
}

type AESGadget struct {
	api   frontend.API
	sbox0 [256]frontend.Variable
	RCon  [11]frontend.Variable
}

// retuns AESGadget instance which can be used inside a circuit
func NewAESGadget(api frontend.API) AESGadget {

	sbox0 := [256]frontend.Variable{
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
	}

	RCon := [11]frontend.Variable{0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

	return AESGadget{api: api, sbox0: sbox0, RCon: RCon}
}

// aes128 encrypt function
func (aes *AESGadget) SubBytes(state [16]frontend.Variable) [16]frontend.Variable {
	var newState [16]frontend.Variable
	for i := 0; i < 16; i++ {
		newState[i] = aes.Subw(aes.sbox0, state[i])
	}
	return newState
}

func (aes *AESGadget) MixColumns(state [16]frontend.Variable) [16]frontend.Variable {

	var a [4]frontend.Variable
	var newState [16]frontend.Variable

	for c := 0; c < 4; c++ {

		a[0] = state[c]
		a[1] = state[4+c]
		a[2] = state[8+c]
		a[3] = state[12+c]

		a0Bits := aes.api.ToBinary(a[0], 8)
		a0gmc3Bits := aes.api.ToBinary(aes.GaloisMulConst(a[0], 3), 8)
		a0gmc2Bits := aes.api.ToBinary(aes.GaloisMulConst(a[0], 2), 8)
		a1Bits := aes.api.ToBinary(a[1], 8)
		a1gmc3Bits := aes.api.ToBinary(aes.GaloisMulConst(a[1], 3), 8)
		a1gmc2Bits := aes.api.ToBinary(aes.GaloisMulConst(a[1], 2), 8)
		a2Bits := aes.api.ToBinary(a[2], 8)
		a2gmc3Bits := aes.api.ToBinary(aes.GaloisMulConst(a[2], 3), 8)
		a2gmc2Bits := aes.api.ToBinary(aes.GaloisMulConst(a[2], 2), 8)
		a3Bits := aes.api.ToBinary(a[3], 8)
		a3gmc3Bits := aes.api.ToBinary(aes.GaloisMulConst(a[3], 3), 8)
		a3gmc2Bits := aes.api.ToBinary(aes.GaloisMulConst(a[3], 2), 8)

		// bitwise xor
		tmp1 := make([]frontend.Variable, 8)
		tmp2 := make([]frontend.Variable, 8) // api.ToBinary(0, 8)
		tmp3 := make([]frontend.Variable, 8)
		tmp4 := make([]frontend.Variable, 8)
		for g := 0; g < 8; g++ {
			tmp1[g] = aes.api.Xor(aes.api.Xor(aes.api.Xor(a0gmc2Bits[g], a1gmc3Bits[g]), a2Bits[g]), a3Bits[g])
			tmp2[g] = aes.api.Xor(aes.api.Xor(aes.api.Xor(a0Bits[g], a1gmc2Bits[g]), a2gmc3Bits[g]), a3Bits[g])
			tmp3[g] = aes.api.Xor(aes.api.Xor(aes.api.Xor(a0Bits[g], a1Bits[g]), a2gmc2Bits[g]), a3gmc3Bits[g])
			tmp4[g] = aes.api.Xor(aes.api.Xor(aes.api.Xor(a0gmc3Bits[g], a1Bits[g]), a2Bits[g]), a3gmc2Bits[g])
		}

		newState[c] = aes.api.FromBinary(tmp1...)
		newState[4+c] = aes.api.FromBinary(tmp2...)
		newState[8+c] = aes.api.FromBinary(tmp3...)
		newState[12+c] = aes.api.FromBinary(tmp4...)
	}

	return newState
}

func (aes *AESGadget) GaloisMulConst(a frontend.Variable, idx int) frontend.Variable {
	p := frontend.Variable(0)
	for counter := 0; counter < 8; counter++ {
		if (idx & 1) != 0 {
			p = aes.VariableXor(p, a, 8)
		}
		idx = idx >> 1
		if idx == 0 {
			counter = 8
			break
		}

		hiBitSet := aes.GetBit(a, 8, 1)
		a = aes.ShiftLeft(a, 8, 1)
		tmp := aes.VariableXor(a, 0x1B, 8)
		a = aes.api.Add(a, aes.api.Mul(hiBitSet, aes.api.Sub(tmp, a)))
	}
	return p
}

func (aes *AESGadget) GetBit(a frontend.Variable, size, idx int) frontend.Variable {
	bits := aes.api.ToBinary(a, size)
	return bits[len(bits)-idx]
}

func (aes *AESGadget) ShiftLeft(a frontend.Variable, size, shift int) frontend.Variable {

	bits := aes.api.ToBinary(a, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		if i < shift {
			x[i] = 0
		} else {
			x[i] = bits[i-shift]
		}
	}
	return aes.api.FromBinary(x...)
}

func (aes *AESGadget) ShiftRows(state [16]frontend.Variable) [16]frontend.Variable {
	var newState [16]frontend.Variable
	for i := 0; i < 4; i++ {
		newState[i] = state[i] // 0, 1, 2, 3 == t0
	}
	for i := 0; i < 4; i++ {
		newState[4+i] = state[4+((i+1)%4)] // 1, 2, 3, 0 == t1
	}
	for i := 0; i < 4; i++ {
		newState[8+i] = state[8+((i+2)%4)] // 2, 3, 0, 1 == t2
	}
	for i := 0; i < 4; i++ {
		newState[12+i] = state[12+((i+3)%4)] // 3, 0, 1, 2 == t3
	}
	return newState
}

// adds xor and shifts bytes in matrix to match next round representation requirements
func (aes *AESGadget) AddRoundKey(state [16]frontend.Variable, expandedKey []frontend.Variable, from int) [16]frontend.Variable {
	var newState [16]frontend.Variable
	for i := 0; i < 4; i++ {
		newState[i] = aes.VariableXor(state[i], expandedKey[from+(4*i)], 8)
		newState[4+i] = aes.VariableXor(state[4+i], expandedKey[from+(4*i)+1], 8)
		newState[8+i] = aes.VariableXor(state[8+i], expandedKey[from+(4*i)+2], 8)
		newState[12+i] = aes.VariableXor(state[12+i], expandedKey[from+(4*i)+3], 8)
	}
	return newState
}

// different re-arrangement of variables
func (aes *AESGadget) AddRoundKey2(state [16]frontend.Variable, expandedKey []frontend.Variable, from int) [16]frontend.Variable {
	var newState [16]frontend.Variable
	ctr := 0
	for i := 0; i < 4; i++ {
		newState[i] = aes.VariableXor(state[i], expandedKey[from+ctr], 8)
		newState[4+i] = aes.VariableXor(state[4+i], expandedKey[from+ctr+1], 8)
		newState[8+i] = aes.VariableXor(state[8+i], expandedKey[from+ctr+2], 8)
		newState[12+i] = aes.VariableXor(state[12+i], expandedKey[from+ctr+3], 8)
		ctr += 4
	}
	return newState
}

// xor on bits of two frontend.Variables
func (aes *AESGadget) VariableXor(a frontend.Variable, b frontend.Variable, size int) frontend.Variable {
	bitsA := aes.api.ToBinary(a, size)
	bitsB := aes.api.ToBinary(b, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		x[i] = aes.api.Xor(bitsA[i], bitsB[i])
	}
	return aes.api.FromBinary(x...)
}

// substitute word with naive lookup of sbox
func (aes *AESGadget) Subw(sbox [256]frontend.Variable, a frontend.Variable) frontend.Variable {
	out := frontend.Variable(0)
	for j := 0; j < 256; j++ {
		out = aes.api.Add(out, aes.api.Mul(aes.api.IsZero(aes.api.Sub(a, j)), sbox[j])) // api.Cmp instead of api.Sub works but is inefficient
	}
	return out
}

func (aes *AESGadget) createIV(counter frontend.Variable, iv []frontend.Variable) {
	aBits := aes.api.ToBinary(counter, 32)

	for i := 0; i < 4; i++ {
		iv[15-i] = aes.api.FromBinary(aBits[i*8 : i*8+8]...)
	}

}
