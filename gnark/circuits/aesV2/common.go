package aes_v2

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

const BLOCKS = 5
const NB = 4

type AESBaseCircuit struct {
	Key     []frontend.Variable
	Nonce   [12]frontend.Variable          `gnark:",public"`
	Counter frontend.Variable              `gnark:",public"`
	In      [BLOCKS * 16]frontend.Variable `gnark:",public"`
}

type AESGadget struct {
	api            frontend.API
	sbox           *logderivlookup.Table
	RCon           [11]frontend.Variable
	t0, t1, t2, t3 *logderivlookup.Table
	keySize        int
}

// retuns AESGadget instance which can be used inside a circuit
func NewAESGadget(api frontend.API, keySize int) AESGadget {

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

	return AESGadget{api: api, sbox: sbox, RCon: RCon, t0: t0, t1: t1, t2: t2, t3: t3, keySize: keySize}
}

func (aes *AESBaseCircuit) Define(api frontend.API, out [BLOCKS * 16]frontend.Variable) error {
	keySize := len(aes.Key)

	if keySize != 16 && keySize != 32 {
		return errors.New("key size must be 16 or 32")
	}

	counter := aes.Counter
	var counterBlock [16]frontend.Variable

	gAes := NewAESGadget(api, keySize)

	for i := 0; i < 12; i++ {
		counterBlock[i] = aes.Nonce[i]
	}
	for b := 0; b < BLOCKS; b++ {
		gAes.createIV(counter, counterBlock[:])
		// encrypt counter under key
		keystream := gAes.Encrypt(aes.Key, counterBlock)

		for i := 0; i < 16; i++ {
			api.AssertIsEqual(out[b*16+i], gAes.VariableXor(keystream[i], aes.In[b*16+i], 8))
		}
		counter = api.Add(counter, 1)
	}
	api.AssertIsEqual(counter, api.Add(aes.Counter, BLOCKS))

	return nil
}

// aes128 encrypt function
func (aes *AESGadget) SubBytes(state [16]frontend.Variable) (res [16]frontend.Variable) {
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

func (aes *AESGadget) Encrypt(key []frontend.Variable, pt [16]frontend.Variable) [16]frontend.Variable {
	keySize := aes.keySize
	rounds := 10
	if keySize == 32 {
		rounds = 14
	}

	// expand key
	xk := aes.ExpandKey(key)
	var state [16]frontend.Variable
	for i := 0; i < 16; i++ {
		state[i] = aes.VariableXor(xk[i], pt[i], 8)
	}

	var t0, t1, t2, t3 []frontend.Variable
	// iterate rounds
	for i := 1; i < rounds; i++ {
		k := i * 16
		t0 = aes.XorSubWords(state[0], state[5], state[10], state[15], xk[k+0:k+4])
		t1 = aes.XorSubWords(state[4], state[9], state[14], state[3], xk[k+4:k+8])
		t2 = aes.XorSubWords(state[8], state[13], state[2], state[7], xk[k+8:k+12])
		t3 = aes.XorSubWords(state[12], state[1], state[6], state[11], xk[k+12:k+16])

		copy(state[:4], t0)
		copy(state[4:8], t1)
		copy(state[8:12], t2)
		copy(state[12:16], t3)
	}

	copy(state[:], aes.ShiftSub(state))

	k := rounds * 16

	for i := 0; i < 4; i++ {
		state[i+0] = aes.VariableXor(state[i+0], xk[k+i+0], 8)
		state[i+4] = aes.VariableXor(state[i+4], xk[k+i+4], 8)
		state[i+8] = aes.VariableXor(state[i+8], xk[k+i+8], 8)
		state[i+12] = aes.VariableXor(state[i+12], xk[k+i+12], 8)
	}

	return state
}

func (aes *AESGadget) ExpandKey(key []frontend.Variable) []frontend.Variable {

	keySize := aes.keySize
	rounds := 10
	if keySize == 32 {
		rounds = 14
	}

	var nWords = NB * (rounds + 1)

	expand := make([]frontend.Variable, nWords*4)
	i := 0

	for i < keySize {
		expand[i] = key[i]
		expand[i+1] = key[i+1]
		expand[i+2] = key[i+2]
		expand[i+3] = key[i+3]

		i += 4
	}

	for i < (nWords * 4) {
		t0 := expand[i-4]
		t1 := expand[i-3]
		t2 := expand[i-2]
		t3 := expand[i-1]

		if i%keySize == 0 {
			// rotation
			t0, t1, t2, t3 = t1, t2, t3, t0

			// sub words
			tt := aes.Subws(aes.sbox, t0, t1, t2, t3)
			t0, t1, t2, t3 = tt[0], tt[1], tt[2], tt[3]

			t0 = aes.VariableXor(t0, aes.RCon[i/keySize], 8)
		}

		if rounds == 14 && i%keySize == 16 {
			// sub words
			tt := aes.Subws(aes.sbox, t0, t1, t2, t3)
			t0, t1, t2, t3 = tt[0], tt[1], tt[2], tt[3]

		}

		expand[i] = aes.VariableXor(expand[i-keySize], t0, 8)
		expand[i+1] = aes.VariableXor(expand[i-keySize+1], t1, 8)
		expand[i+2] = aes.VariableXor(expand[i-keySize+2], t2, 8)
		expand[i+3] = aes.VariableXor(expand[i-keySize+3], t3, 8)

		i += 4
	}

	return expand
}
