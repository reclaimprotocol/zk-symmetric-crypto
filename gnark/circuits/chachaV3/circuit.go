package chachaV3

import "github.com/consensys/gnark/frontend"

type ChaChaCircuit struct {
	ChaChaBaseCircuit
	Out [16 * Blocks][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *ChaChaCircuit) Define(api frontend.API) error {

	err := c.ChaChaBaseCircuit.Define(api, c.Out)
	if err != nil {
		return err
	}
	return nil
}
