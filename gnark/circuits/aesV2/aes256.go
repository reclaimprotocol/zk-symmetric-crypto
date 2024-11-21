package aes_v2

import (
	"github.com/consensys/gnark/frontend"
)

type AES256Wrapper struct {
	AESWrapper
}

func (circuit *AES256Wrapper) Define(api frontend.API) error {
	return circuit.AESWrapper.Define(api, 32)
}
