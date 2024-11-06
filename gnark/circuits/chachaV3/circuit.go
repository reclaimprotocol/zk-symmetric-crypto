package chachaV3

import (
	"gnark-symmetric-crypto/utils"

	"github.com/consensys/gnark/frontend"
)

const Blocks = 1

type ChaChaCircuit struct {
	Key     [8][BITS_PER_WORD]frontend.Variable
	Counter [BITS_PER_WORD]frontend.Variable              `gnark:",public"`
	Nonce   [3][BITS_PER_WORD]frontend.Variable           `gnark:",public"`
	In      [16 * Blocks][BITS_PER_WORD]frontend.Variable `gnark:",public"`
	Out     [16 * Blocks][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *ChaChaCircuit) Define(api frontend.API) error {

	var state [16][BITS_PER_WORD]frontend.Variable
	counter := c.Counter

	var one [BITS_PER_WORD]frontend.Variable
	copy(one[:], api.ToBinary(1, 32))

	c1 := utils.Uint32ToBits(0x61707865)
	c2 := utils.Uint32ToBits(0x3320646e)
	c3 := utils.Uint32ToBits(0x79622d32)
	c4 := utils.Uint32ToBits(0x6b206574)
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
		var ciphertext [16][BITS_PER_WORD]frontend.Variable
		for i, s := range state {
			xor32(api, &c.In[b*16+i], &s, &ciphertext[i])
		}

		// check that output matches ciphertext
		for i := 0; i < 16; i++ {
			for j := 0; j < BITS_PER_WORD; j++ {
				api.AssertIsEqual(c.Out[b*16+i][j], ciphertext[i][j])
			}
		}
		// increment counter for next block
		// add32(api, &counter, &one)
	}

	return nil
}
