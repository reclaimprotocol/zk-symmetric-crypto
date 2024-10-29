package chacha

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const Blocks = 1

type ChaChaCircuit struct {
	Key     [8]uints.U32
	Counter uints.U32
	Nonce   [3]uints.U32
	In      [16 * Blocks]uints.U32 `gnark:",public"`
	Out     [16 * Blocks]uints.U32 `gnark:",public"`
}

func (c *ChaChaCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	var state [16]uints.U32
	one := uints.NewU32(1)
	counter := c.Counter

	for b := 0; b < Blocks; b++ {
		// Fill state. Start with constants
		state[0] = uints.NewU32(0x61707865)
		state[1] = uints.NewU32(0x3320646e)
		state[2] = uints.NewU32(0x79622d32)
		state[3] = uints.NewU32(0x6b206574)

		// set key
		copy(state[4:], c.Key[:])
		// set counter
		state[12] = counter
		// set nonce
		copy(state[13:], c.Nonce[:])
		// modify state with round function
		Round(uapi, &state)
		// produce keystream from state
		Serialize(uapi, &state)

		// xor keystream with input
		var ciphertext [16]uints.U32
		for i, s := range state {
			ciphertext[i] = uapi.Xor(c.In[b*16+i], s)
		}

		// check that output matches ciphertext
		for i := 0; i < 16; i++ {
			uapi.AssertEq(c.Out[b*16+i], ciphertext[i])
		}

		// increment counter for next block
		counter = uapi.Add(counter, one)
	}

	return nil
}
