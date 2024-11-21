package aes_v2

import "github.com/consensys/gnark/frontend"

type AESCircuit struct {
	AESBaseCircuit
	Out [BLOCKS * 16]frontend.Variable `gnark:",public"`
}

func (c *AESCircuit) Define(api frontend.API) error {
	return c.AESBaseCircuit.Define(api, c.Out)
}
