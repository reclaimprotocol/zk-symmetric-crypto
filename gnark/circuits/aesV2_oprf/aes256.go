package aes_v2_oprf

import (
	"github.com/consensys/gnark/frontend"
)

// columns

type AES256Wrapper struct {
	AESWrapper
}

func (circuit *AES256Wrapper) Define(api frontend.API) error {
	return circuit.AESWrapper.Define(api, 32)
}
