package impl

import "C"
import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	"gnark-symmetric-crypto/circuits/chachaV3"

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
	Nonces   [][]uint8    `json:"nonces"`   // Array of nonces, one per block
	Counters []uint32     `json:"counters"` // Array of counters, one per block
	Input    []uint8      `json:"input"`    // usually it's redacted ciphertext
	TOPRF    *TOPRFParams `json:"toprf"`
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

// Wrapper functions for backward compatibility with single nonce/counter API
// These functions internally create arrays for the circuit requirements

// VerifyChaCha20 verifies a ChaCha20 proof with a single nonce and counter
// It internally creates the expected public signals format with arrays
func VerifyChaCha20(proof []byte, ciphertext []byte, nonce []byte, counter uint32, input []byte) bool {
	// Build public signals: ciphertext + nonces + counters + input
	signals := ciphertext

	// Append nonces for each block
	for b := 0; b < chachaV3.Blocks; b++ {
		signals = append(signals, nonce...)
	}

	// Append counters for each block (little-endian)
	for b := 0; b < chachaV3.Blocks; b++ {
		bCounter := make([]byte, 4)
		binary.LittleEndian.PutUint32(bCounter, counter+uint32(b))
		signals = append(signals, bCounter...)
	}

	signals = append(signals, input...)

	inParams := &InputVerifyParams{
		Cipher:        "chacha20",
		Proof:         proof,
		PublicSignals: signals,
	}

	buf, err := json.Marshal(inParams)
	if err != nil {
		return false
	}

	return Verify(buf)
}

// VerifyAES128 verifies an AES-128-CTR proof with a single nonce and counter
// It internally creates the expected public signals format with arrays
func VerifyAES128(proof []byte, ciphertext []byte, nonce []byte, counter uint32, input []byte) bool {
	// Build public signals: ciphertext + nonces + counters + input
	signals := ciphertext

	// Append nonces for each block
	for b := 0; b < aes_v2.BLOCKS; b++ {
		signals = append(signals, nonce...)
	}

	// Append counters for each block (big-endian for AES)
	for b := 0; b < aes_v2.BLOCKS; b++ {
		bCounter := make([]byte, 4)
		binary.BigEndian.PutUint32(bCounter, counter+uint32(b))
		signals = append(signals, bCounter...)
	}

	signals = append(signals, input...)

	inParams := &InputVerifyParams{
		Cipher:        "aes-128-ctr",
		Proof:         proof,
		PublicSignals: signals,
	}

	buf, err := json.Marshal(inParams)
	if err != nil {
		return false
	}

	return Verify(buf)
}

// VerifyAES256 verifies an AES-256-CTR proof with a single nonce and counter
// It internally creates the expected public signals format with arrays
func VerifyAES256(proof []byte, ciphertext []byte, nonce []byte, counter uint32, input []byte) bool {
	// Build public signals: ciphertext + nonces + counters + input
	signals := ciphertext

	// Append nonces for each block
	for b := 0; b < aes_v2.BLOCKS; b++ {
		signals = append(signals, nonce...)
	}

	// Append counters for each block (big-endian for AES)
	for b := 0; b < aes_v2.BLOCKS; b++ {
		bCounter := make([]byte, 4)
		binary.BigEndian.PutUint32(bCounter, counter+uint32(b))
		signals = append(signals, bCounter...)
	}

	signals = append(signals, input...)

	inParams := &InputVerifyParams{
		Cipher:        "aes-256-ctr",
		Proof:         proof,
		PublicSignals: signals,
	}

	buf, err := json.Marshal(inParams)
	if err != nil {
		return false
	}

	return Verify(buf)
}

// VerifyChaCha20OPRF verifies a ChaCha20 OPRF proof with arrays of nonces and counters
func VerifyChaCha20OPRF(proof []byte, nonces [][]uint8, counters []uint32, input []byte, toprf *TOPRFParams) bool {
	oprfParams := &InputTOPRFParams{
		Nonces:   nonces,
		Counters: counters,
		Input:    input,
		TOPRF:    toprf,
	}

	publicSignals, err := json.Marshal(oprfParams)
	if err != nil {
		return false
	}

	inParams := &InputVerifyParams{
		Cipher:        "chacha20-toprf",
		Proof:         proof,
		PublicSignals: publicSignals,
	}

	buf, err := json.Marshal(inParams)
	if err != nil {
		return false
	}

	return Verify(buf)
}

// VerifyAES128OPRF verifies an AES-128-CTR OPRF proof with arrays of nonces and counters
func VerifyAES128OPRF(proof []byte, nonces [][]uint8, counters []uint32, input []byte, toprf *TOPRFParams) bool {
	oprfParams := &InputTOPRFParams{
		Nonces:   nonces,
		Counters: counters,
		Input:    input,
		TOPRF:    toprf,
	}

	publicSignals, err := json.Marshal(oprfParams)
	if err != nil {
		return false
	}

	inParams := &InputVerifyParams{
		Cipher:        "aes-128-ctr-toprf",
		Proof:         proof,
		PublicSignals: publicSignals,
	}

	buf, err := json.Marshal(inParams)
	if err != nil {
		return false
	}

	return Verify(buf)
}

// VerifyAES256OPRF verifies an AES-256-CTR OPRF proof with arrays of nonces and counters
func VerifyAES256OPRF(proof []byte, nonces [][]uint8, counters []uint32, input []byte, toprf *TOPRFParams) bool {
	oprfParams := &InputTOPRFParams{
		Nonces:   nonces,
		Counters: counters,
		Input:    input,
		TOPRF:    toprf,
	}

	publicSignals, err := json.Marshal(oprfParams)
	if err != nil {
		return false
	}

	inParams := &InputVerifyParams{
		Cipher:        "aes-256-ctr-toprf",
		Proof:         proof,
		PublicSignals: publicSignals,
	}

	buf, err := json.Marshal(inParams)
	if err != nil {
		return false
	}

	return Verify(buf)
}
