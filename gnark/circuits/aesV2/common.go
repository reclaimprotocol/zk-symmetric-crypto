package aes_v2

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

const BLOCKS = 4

type AESWrapper struct {
	Key        []frontend.Variable
	Nonce      [12]frontend.Variable          `gnark:",public"`
	Counter    frontend.Variable              `gnark:",public"`
	Plaintext  [BLOCKS * 16]frontend.Variable `gnark:",public"`
	Ciphertext [BLOCKS * 16]frontend.Variable `gnark:",public"`
}

type AESGadget struct {
	api            frontend.API
	sbox           *logderivlookup.Table
	RCon           [11]frontend.Variable
	t0, t1, t2, t3 *logderivlookup.Table
}

// retuns AESGadget instance which can be used inside a circuit
func NewAESGadget(api frontend.API) AESGadget {

	t0 := logderivlookup.New(api)
	t1 := logderivlookup.New(api)
	t2 := logderivlookup.New(api)
	t3 := logderivlookup.New(api)
	sbox := logderivlookup.New(api)
	for i := 0; i < 256; i++ {
		t0.Insert(T[0][i])
		t1.Insert(T[1][i])
		t2.Insert(T[2][i])
		t3.Insert(T[3][i])
		sbox.Insert(sbox0[i])
	}

	RCon := [11]frontend.Variable{0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}

	return AESGadget{api: api, sbox: sbox, RCon: RCon, t0: t0, t1: t1, t2: t2, t3: t3}
}

// aes128 encrypt function
func (aes *AESGadget) SubBytes(state [16]frontend.Variable) (res [16]frontend.Variable) {
	/*var newState [16]frontend.Variable
	for i := 0; i < 16; i++ {
		newState[i] = aes.Subw(aes.sbox, state[i])
	}*/
	t := aes.Subws(aes.sbox, state[:]...)
	copy(res[:], t)
	return res
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

func (aes *AESGadget) XorSubWords(a, b, c, d frontend.Variable, xk []frontend.Variable) []frontend.Variable {

	aa := aes.t0.Lookup(a)[0]
	bb := aes.t1.Lookup(b)[0]
	cc := aes.t2.Lookup(c)[0]
	dd := aes.t3.Lookup(d)[0]

	t0 := aes.api.ToBinary(aa, 32)
	t1 := aes.api.ToBinary(bb, 32)
	t2 := aes.api.ToBinary(cc, 32)
	t3 := aes.api.ToBinary(dd, 32)

	t4 := append(aes.api.ToBinary(xk[0], 8), aes.api.ToBinary(xk[1], 8)...)
	t4 = append(t4, aes.api.ToBinary(xk[2], 8)...)
	t4 = append(t4, aes.api.ToBinary(xk[3], 8)...)

	t := make([]frontend.Variable, 32)
	for i := 0; i < 32; i++ {
		t[i] = aes.api.Xor(t0[i], t1[i])
		t[i] = aes.api.Xor(t[i], t2[i])
		t[i] = aes.api.Xor(t[i], t3[i])
		t[i] = aes.api.Xor(t[i], t4[i])
	}

	newWord := make([]frontend.Variable, 4)
	newWord[0] = aes.api.FromBinary(t[:8]...)
	newWord[1] = aes.api.FromBinary(t[8:16]...)
	newWord[2] = aes.api.FromBinary(t[16:24]...)
	newWord[3] = aes.api.FromBinary(t[24:32]...)
	return newWord
}

func (aes *AESGadget) ShiftSub(state [16]frontend.Variable) []frontend.Variable {
	t := make([]frontend.Variable, 16)
	for i := 0; i < 16; i++ {
		t[i] = state[byte_order[i]]
	}
	return aes.Subws(aes.sbox, t...)
}

// substitute word with naive lookup of sbox
func (aes *AESGadget) Subws(sbox *logderivlookup.Table, a ...frontend.Variable) []frontend.Variable {
	return sbox.Lookup(a...)
}

func (aes *AESGadget) createIV(counter frontend.Variable, iv []frontend.Variable) {
	aBits := aes.api.ToBinary(counter, 32)

	for i := 0; i < 4; i++ {
		iv[15-i] = aes.api.FromBinary(aBits[i*8 : i*8+8]...)
	}

}
