package aes_v2_oprf

import (
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	"gnark-symmetric-crypto/circuits/toprf"

	"github.com/consensys/gnark/frontend"
)

type AESTOPRFCircuit struct {
	aes_v2.AESBaseCircuit
	Out     [aes_v2.BLOCKS * 16]frontend.Variable
	Bitmask [aes_v2.BLOCKS * 16 * 8]frontend.Variable `gnark:",public"` // bit mask for bytes being hashed
	// Length of "secret data" elements to be hashed. In bytes
	Len   frontend.Variable `gnark:",public"`
	TOPRF toprf.Params
}

func (c *AESTOPRFCircuit) Define(api frontend.API) error {

	err := c.AESBaseCircuit.Define(api, c.Out)
	if err != nil {
		return err
	}

	outBits := make([]frontend.Variable, len(c.Out)*8)

	// flatten result bits array
	for i := 0; i < len(c.Out); i++ {
		bits := api.ToBinary(c.Out[i], 8)
		for j := 0; j < 8; j++ {
			outBits[i*8+j] = bits[j]
		}
	}

	return toprf.VerifyTOPRF(api, &c.TOPRF, toprf.ExtractSecretElements(api, outBits, c.Bitmask[:], c.Len))
}
