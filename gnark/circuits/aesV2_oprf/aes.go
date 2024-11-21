package aes_v2_oprf

import (
	"gnark-symmetric-crypto/circuits/toprf"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
)

const BLOCKS = 5
const NB = 4
const BytesPerElement = 31

type TOPRFData struct {
	DomainSeparator frontend.Variable `gnark:",public"`
	Mask            frontend.Variable

	EvaluatedElements [toprf.Threshold]twistededwards.Point `gnark:",public"` // responses per each node
	Coefficients      [toprf.Threshold]frontend.Variable    `gnark:",public"` // coeffs for reconstructing element

	// Proofs of DLEQ per node
	PublicKeys [toprf.Threshold]twistededwards.Point `gnark:",public"`
	C          [toprf.Threshold]frontend.Variable    `gnark:",public"`
	R          [toprf.Threshold]frontend.Variable    `gnark:",public"`

	Output frontend.Variable `gnark:",public"`
}

type AESWrapper struct {
	Key     []frontend.Variable
	Nonce   [12]frontend.Variable              `gnark:",public"`
	Counter frontend.Variable                  `gnark:",public"`
	In      [BLOCKS * 16]frontend.Variable     `gnark:",public"`
	Out     [BLOCKS * 16]frontend.Variable     // plaintext
	Bitmask [BLOCKS * 16 * 8]frontend.Variable `gnark:",public"` // bit mask for bytes being hashed

	// Length of "secret data" elements to be hashed. In bytes
	Len frontend.Variable `gnark:",public"`

	TOPRF TOPRFData
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

func (aes *AESWrapper) Define(api frontend.API) error {
	counter := aes.Counter
	var counterBlock [16]frontend.Variable

	gAes := NewAESGadget(api, len(aes.Key))

	for i := 0; i < 12; i++ {
		counterBlock[i] = aes.Nonce[i]
	}
	for b := 0; b < BLOCKS; b++ {
		gAes.createIV(counter, counterBlock[:])
		// encrypt counter under key
		keystream := gAes.Encrypt(aes.Key, counterBlock)

		for i := 0; i < 16; i++ {
			api.AssertIsEqual(aes.Out[b*16+i], gAes.VariableXor(keystream[i], aes.In[b*16+i], 8))
		}
		counter = api.Add(counter, 1)
	}
	api.AssertIsEqual(counter, api.Add(aes.Counter, BLOCKS))

	return aes.TOPRFVerify(api)
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
			// subwords
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

func (circuit *AESWrapper) TOPRFVerify(api frontend.API) error {
	outBits := make([]frontend.Variable, len(circuit.Out)*8)

	// flatten result bits array
	for i := 0; i < len(circuit.Out); i++ {
		bits := api.ToBinary(circuit.Out[i], 8)
		for j := 0; j < 8; j++ {
			outBits[i*8+j] = bits[j]
		}
	}

	pow1 := frontend.Variable(1)
	pow2 := frontend.Variable(0)
	res1 := frontend.Variable(0)
	res2 := frontend.Variable(0)
	totalBits := frontend.Variable(0)

	for i := 0; i < len(outBits); i++ {
		bitIndex := i
		bitIsSet := circuit.Bitmask[bitIndex]
		bit := api.Select(bitIsSet, outBits[bitIndex], 0)

		res1 = api.Add(res1, api.Mul(bit, pow1))
		res2 = api.Add(res2, api.Mul(bit, pow2))

		n := api.Add(bitIsSet, 1) // do we need to multiply power by 2?
		pow2 = api.Mul(pow2, n)
		pow1 = api.Mul(pow1, n)

		totalBits = api.Add(totalBits, bitIsSet)

		r1Done := api.IsZero(api.Sub(totalBits, BytesPerElement*8)) // are we done with 1st number?
		pow1 = api.Mul(pow1, api.Sub(1, r1Done))                    // set pow1 to zero if yes
		pow2 = api.Add(pow2, r1Done)                                // set pow2 to 1 to start increasing

	}

	api.AssertIsDifferent(circuit.Len, 0) // Len != 0

	comparator := cmp.NewBoundedComparator(api, big.NewInt(512), false) // max diff is 512-496
	comparator.AssertIsLessEq(totalBits, BytesPerElement*8*2)           // check that number of processed bits <= 62 bytes
	api.AssertIsEqual(totalBits, api.Mul(circuit.Len, 8))               // and that it corresponds to Len

	// check that TOPRF output was created from secret data by a server with a specific public key
	oprfData := &toprf.TOPRFParams{
		SecretData:      [2]frontend.Variable{res1, res2},
		DomainSeparator: circuit.TOPRF.DomainSeparator,
		Mask:            circuit.TOPRF.Mask,
		Responses:       circuit.TOPRF.EvaluatedElements,
		Coefficients:    circuit.TOPRF.Coefficients,
		Output:          circuit.TOPRF.Output,
		SharePublicKeys: circuit.TOPRF.PublicKeys,
		C:               circuit.TOPRF.C,
		R:               circuit.TOPRF.R,
	}
	return toprf.VerifyTOPRF(api, oprfData)
}
