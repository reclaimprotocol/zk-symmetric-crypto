package chachaV3_oprf

import (
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/circuits/toprf"

	"github.com/consensys/gnark/frontend"
)

const BITS_PER_WORD = 32
const TOTAL_BITS = 16 * chachaV3.Blocks * BITS_PER_WORD

type ChachaTOPRFCircuit struct {
	chachaV3.ChaChaBaseCircuit
	Out     [16 * chachaV3.Blocks][BITS_PER_WORD]frontend.Variable // plaintext
	Bitmask [TOTAL_BITS]frontend.Variable                          `gnark:",public"` // bit mask for bits being hashed
	Len     frontend.Variable                                      `gnark:",public"` // Length of "secret data" elements to be hashed. In bytes

	TOPRF toprf.Params
}

func (c *ChachaTOPRFCircuit) Define(api frontend.API) error {
	err := c.ChaChaBaseCircuit.Define(api, c.Out)
	if err != nil {
		return err
	}

	outBits := make([]frontend.Variable, TOTAL_BITS)
	// flatten result bits array
	for i := 0; i < len(c.Out); i++ {
		word := i * 32
		for j := 0; j < BITS_PER_WORD; j++ {
			nByte := 3 - j/8 // switch endianness back to original
			outBits[word+j] = c.Out[i][nByte*8+j%8]
		}
	}

	return toprf.VerifyTOPRF(api, &c.TOPRF, toprf.ExtractSecretElements(api, outBits, c.Bitmask[:], c.Len))
}
