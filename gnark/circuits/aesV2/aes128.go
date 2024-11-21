package aes_v2

import (
	"github.com/consensys/gnark/frontend"
)

type AES128Wrapper struct {
	AESWrapper
}

func (circuit *AES128Wrapper) Define(api frontend.API) error {
	return circuit.AESWrapper.Define(api, 16)
}
