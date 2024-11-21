package impl

import "C"
import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/logger"
)

type InputVerifyParams struct {
	Cipher        string  `json:"cipher"`
	Proof         []uint8 `json:"proof"`
	PublicSignals []uint8 `json:"publicSignals"`
}

type TOPRFResponse struct {
	Index          uint8   `json:"index"`
	PublicKeyShare []byte  `json:"publicKeyShare"`
	Evaluated      []uint8 `json:"evaluated"`
	C              []byte  `json:"c"`
	R              []byte  `json:"r"`
}

type TOPRFParams struct {
	Pos             uint32           `json:"pos"`
	Len             uint32           `json:"len"`
	Mask            []uint8          `json:"mask"`
	DomainSeparator []uint8          `json:"domainSeparator"`
	Output          []uint8          `json:"output"`
	Responses       []*TOPRFResponse `json:"responses"`
}

type InputTOPRFParams struct {
	Nonce   []uint8      `json:"nonce"`
	Counter uint32       `json:"counter"`
	Input   []uint8      `json:"input"` // usually it's redacted ciphertext
	TOPRF   *TOPRFParams `json:"toprf"`
}

var verifiers = make(map[string]Verifier)

//go:embed generated/vk.chacha20
var vkChachaEmbedded []byte

//go:embed generated/vk.aes128
var vkAES128Embedded []byte

//go:embed generated/vk.aes256
var vkAES256Embedded []byte

//go:embed generated/vk.chacha20_oprf
var vkChachaOPRFEmbedded []byte

//go:embed generated/vk.aes128_oprf
var vkAES128OPRFEmbedded []byte

//go:embed generated/vk.aes256_oprf
var vkAES256OPRFEmbedded []byte

func init() {
	logger.Disable()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err := vk.ReadFrom(bytes.NewBuffer(vkChachaEmbedded))
	if err != nil {
		panic(err)
	}

	verifiers["chacha20"] = &ChachaVerifier{vk: vk}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkAES128Embedded))
	if err != nil {
		panic(err)
	}

	verifiers["aes-128-ctr"] = &AESVerifier{vk: vk}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkAES256Embedded))
	if err != nil {
		panic(err)
	}

	verifiers["aes-256-ctr"] = &AESVerifier{vk: vk}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkChachaOPRFEmbedded))
	if err != nil {
		panic(err)
	}

	verifiers["chacha20-toprf"] = &ChachaOPRFVerifier{vk: vk}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkAES128OPRFEmbedded))
	if err != nil {
		panic(err)
	}

	verifiers["aes-128-ctr-toprf"] = &AESOPRFVerifier{vk: vk}

	vk = groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewBuffer(vkAES256OPRFEmbedded))
	if err != nil {
		panic(err)
	}

	verifiers["aes-256-ctr-toprf"] = &AESOPRFVerifier{vk: vk}
}

func Verify(params []byte) (res bool) {

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			res = false
		}
	}()

	var inputParams *InputVerifyParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		fmt.Println(err)
		return false
	}

	if verifier, ok := verifiers[inputParams.Cipher]; ok {
		return verifier.Verify(inputParams.Proof, inputParams.PublicSignals)
	}
	return false
}
