package aes_v2_oprf

import (
	"gnark-symmetric-crypto/circuits/toprf"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/cmp"
)

const BLOCKS = 4 * 2
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
	Out     [BLOCKS * 16]frontend.Variable     `gnark:",public"`
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

	comparator := cmp.NewBoundedComparator(api, big.NewInt(int64(len(outBits)-BytesPerElement*8*2)), false) // max diff is 1024-496
	comparator.AssertIsLessEq(totalBits, BytesPerElement*8*2)                                               // check that number of processed bits <= 62 bytes
	api.AssertIsEqual(totalBits, api.Mul(circuit.Len, 8))                                                   // and that it corresponds to Len

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
