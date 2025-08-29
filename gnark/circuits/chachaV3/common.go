package chachaV3

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

const Blocks = 2

type ChaChaBaseCircuit struct {
	Key     [8][BITS_PER_WORD]frontend.Variable
	Counter [Blocks][BITS_PER_WORD]frontend.Variable      `gnark:",public"`
	Nonce   [Blocks][3][BITS_PER_WORD]frontend.Variable   `gnark:",public"`
	In      [16 * Blocks][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *ChaChaBaseCircuit) Define(api frontend.API, out [16 * Blocks][BITS_PER_WORD]frontend.Variable) error {

	var state [16][BITS_PER_WORD]frontend.Variable

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
		// set per-block counter
		state[12] = c.Counter[b]
		// set per-block nonce
		copy(state[13:], c.Nonce[b][:])
		// modify state with round function
		Round(api, &state)
		// produce keystream from state
		Serialize(&state)

		// xor keystream with input
		var output [16][BITS_PER_WORD]frontend.Variable
		for i, s := range state {
			xor32(api, &c.In[b*16+i], &s, &output[i])
		}

		// check that output matches ciphertext
		for i := 0; i < 16; i++ {
			for j := 0; j < BITS_PER_WORD; j++ {
				api.AssertIsEqual(out[b*16+i][j], output[i][j])
			}
		}
	}

	return nil
}
