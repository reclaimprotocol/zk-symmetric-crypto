package chachaV3_oprf

import (
	"gnark-symmetric-crypto/circuits/toprf"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
)

const Blocks = 2
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

type ChachaTOPRFCircuit struct {
	Key     [8][BITS_PER_WORD]frontend.Variable
	Counter [BITS_PER_WORD]frontend.Variable               `gnark:",public"`
	Nonce   [3][BITS_PER_WORD]frontend.Variable            `gnark:",public"`
	In      [16 * Blocks][BITS_PER_WORD]frontend.Variable  `gnark:",public"` // ciphertext
	Out     [16 * Blocks][BITS_PER_WORD]frontend.Variable  // plaintext
	Bitmask [16 * Blocks * BITS_PER_WORD]frontend.Variable `gnark:",public"` // bit mask for bits being hashed

	// Length of "secret data" elements to be hashed. In bytes
	Len frontend.Variable `gnark:",public"`

	TOPRF TOPRFData
}

func (c *ChachaTOPRFCircuit) Define(api frontend.API) error {
	outBits := make([]frontend.Variable, 16*Blocks*BITS_PER_WORD)
	var state [16][BITS_PER_WORD]frontend.Variable
	counter := c.Counter

	var one [BITS_PER_WORD]frontend.Variable
	copy(one[:], api.ToBinary(1, 32))

	c1 := bits.ToBinary(api, 0x61707865, bits.WithNbDigits(32))
	c2 := bits.ToBinary(api, 0x3320646e, bits.WithNbDigits(32))
	c3 := bits.ToBinary(api, 0x79622d32, bits.WithNbDigits(32))
	c4 := bits.ToBinary(api, 0x6b206574, bits.WithNbDigits(32))
	for b := 0; b < Blocks; b++ {
		// Fill state. Start with constants

		copy(state[0][:], c1[:])
		copy(state[1][:], c2[:])
		copy(state[2][:], c3[:])
		copy(state[3][:], c4[:])

		// set key
		copy(state[4:], c.Key[:])
		// set counter
		state[12] = counter
		// set nonce
		copy(state[13:], c.Nonce[:])
		// modify state with round function
		Round(api, &state)
		// produce keystream from state
		Serialize(&state)

		// xor keystream with input
		var output [16][BITS_PER_WORD]frontend.Variable
		for i, s := range state {
			xor32(api, &c.In[b*16+i], &s, &output[i])
		}

		// check that output matches calculated output
		for i := 0; i < 16; i++ {
			for j := 0; j < BITS_PER_WORD; j++ {
				api.AssertIsEqual(c.Out[b*16+i][j], output[i][j])
			}
		}
		// increment counter for next block
		if b+1 < Blocks {
			add32(api, &counter, &one)
		}
	}

	// flatten result bits array
	for i := 0; i < len(c.Out); i++ {
		word := i * 32
		for j := 0; j < BITS_PER_WORD; j++ {
			nByte := 3 - j/8 // switch endianness back to original
			outBits[word+j] = c.Out[i][nByte*8+j%8]
		}
	}

	pow1 := frontend.Variable(1)
	pow2 := frontend.Variable(0)
	res1 := frontend.Variable(0)
	res2 := frontend.Variable(0)
	totalBits := frontend.Variable(0)

	for i := 0; i < 16*Blocks*BITS_PER_WORD; i++ {
		bitIndex := i
		bitIsSet := c.Bitmask[bitIndex]
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

	api.AssertIsDifferent(c.Len, 0) // Len != 0

	comparator := cmp.NewBoundedComparator(api, big.NewInt(16*Blocks*BITS_PER_WORD-BytesPerElement*8*2), false) // max diff is 1024-496
	comparator.AssertIsLessEq(totalBits, BytesPerElement*8*2)                                                   // check that number of processed bits <= 62 bytes
	api.AssertIsEqual(totalBits, api.Mul(c.Len, 8))                                                             // and that it corresponds to Len

	// check that TOPRF output was created from secret data by a server with a specific public key
	oprfData := &toprf.TOPRFParams{
		SecretData:      [2]frontend.Variable{res1, res2},
		DomainSeparator: c.TOPRF.DomainSeparator,
		Mask:            c.TOPRF.Mask,
		Responses:       c.TOPRF.EvaluatedElements,
		Coefficients:    c.TOPRF.Coefficients,
		Output:          c.TOPRF.Output,
		SharePublicKeys: c.TOPRF.PublicKeys,
		C:               c.TOPRF.C,
		R:               c.TOPRF.R,
	}
	return toprf.VerifyTOPRF(api, oprfData)
}
