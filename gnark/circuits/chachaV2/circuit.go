package chachaV2

import (
	"github.com/consensys/gnark/frontend"
)

const Blocks = 1

type ChaChaCircuit struct {
	Key     [8]frontend.Variable
	Counter frontend.Variable
	Nonce   [3]frontend.Variable
	In      [16 * Blocks]frontend.Variable `gnark:",public"`
	Out     [16 * Blocks]frontend.Variable `gnark:",public"`
}

func (c *ChaChaCircuit) Define(api frontend.API) error {

	var state [16]frontend.Variable
	counter := c.Counter

	for b := 0; b < Blocks; b++ {
		// Fill state. Start with constants
		state[0] = 0x61707865
		state[1] = 0x3320646e
		state[2] = 0x79622d32
		state[3] = 0x6b206574

		// set key
		copy(state[4:], c.Key[:])
		// set counter
		state[12] = counter
		// set nonce
		copy(state[13:], c.Nonce[:])
		// modify state with round function
		Round(api, &state)
		// produce keystream from state
		Serialize(api, &state)

		// xor keystream with input
		var ciphertext [16]frontend.Variable
		for i, s := range state {
			ciphertext[i] = xor32(api, c.In[b*16+i], s)
		}

		// check that output matches ciphertext
		for i := 0; i < 16; i++ {
			api.AssertIsEqual(c.Out[b*16+i], ciphertext[i])
		}

		// increment counter for next block
		counter = add32(api, counter, 1)
	}

	return nil
}
