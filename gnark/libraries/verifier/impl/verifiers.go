package impl

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	aes_v2_oprf "gnark-symmetric-crypto/circuits/aesV2_oprf"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/circuits/chachaV3_oprf"
	"gnark-symmetric-crypto/circuits/toprf"
	"gnark-symmetric-crypto/utils"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type Verifier interface {
	Verify(proof []byte, publicSignals []uint8) bool
}

type ChachaVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaVerifier) Verify(proof []byte, publicSignals []uint8) bool {
	chunkLen := 64 * chachaV3.Blocks
	// Updated to handle per-block nonce and counter: in & out, nonces (12 bytes * blocks), counters (4 bytes * blocks)
	pubLen := chunkLen*2 + 12*chachaV3.Blocks + 4*chachaV3.Blocks
	if len(publicSignals) != pubLen {
		fmt.Printf("public signals must be %d bytes, not %d\n", pubLen, len(publicSignals))
		return false
	}

	witness := &chachaV3.ChaChaCircuit{}

	offset := 0
	bOut := publicSignals[offset:chunkLen]
	offset += chunkLen

	// Extract per-block nonces and counters
	for b := 0; b < chachaV3.Blocks; b++ {
		bNonce := publicSignals[offset : offset+12]
		offset += 12
		nonce := utils.BytesToUint32LEBits(bNonce)
		copy(witness.Nonce[b][:], nonce)
	}

	for b := 0; b < chachaV3.Blocks; b++ {
		bCounter := publicSignals[offset : offset+4]
		offset += 4
		counter := utils.BytesToUint32LEBits(bCounter)
		witness.Counter[b] = counter[0]
	}

	bIn := publicSignals[offset:]

	out := utils.BytesToUint32BEBits(bOut)
	in := utils.BytesToUint32BEBits(bIn)

	copy(witness.In[:], in)
	copy(witness.Out[:], out)

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, cv.vk, wtns)
	if err != nil {
		fmt.Println(err)
	}
	return err == nil
}

type AESVerifier struct {
	vk groth16.VerifyingKey
}

func (av *AESVerifier) Verify(bProof []byte, publicSignals []uint8) bool {

	bytesPerInput := aes_v2.BLOCKS * 16
	// Updated to handle per-block nonce and counter: ciphertext, nonces (12 bytes * blocks), counters (4 bytes * blocks), plaintext
	expectedLen := bytesPerInput*2 + 12*aes_v2.BLOCKS + 4*aes_v2.BLOCKS

	if len(publicSignals) != expectedLen {
		fmt.Printf("public signals must be %d bytes, not %d\n", expectedLen, len(publicSignals))
		return false
	}

	witness := &aes_v2.AESCircuit{
		AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, 1)}, // avoid warnings
	}

	offset := 0
	ciphertext := publicSignals[offset : offset+bytesPerInput]
	offset += bytesPerInput

	// Extract per-block nonces and counters
	for b := 0; b < aes_v2.BLOCKS; b++ {
		nonce := publicSignals[offset : offset+12]
		offset += 12
		for i := 0; i < 12; i++ {
			witness.Nonce[b][i] = nonce[i]
		}
	}

	for b := 0; b < aes_v2.BLOCKS; b++ {
		bCounter := publicSignals[offset : offset+4]
		offset += 4
		witness.Counter[b] = binary.BigEndian.Uint32(bCounter)
	}

	plaintext := publicSignals[offset:]

	for i := 0; i < len(plaintext); i++ {
		witness.In[i] = plaintext[i]
		witness.Out[i] = ciphertext[i]
	}

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(bProof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, av.vk, wtns)
	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}

type ChachaOPRFVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaOPRFVerifier) Verify(proof []byte, publicSignals []uint8) bool {
	var iParams *InputTOPRFParams
	err := json.Unmarshal(publicSignals, &iParams)
	if err != nil {
		fmt.Println(err)
		return false
	}

	oprf := iParams.TOPRF
	if oprf == nil || oprf.Responses == nil {
		fmt.Println("TOPRF params are empty")
		return false
	}

	resps := oprf.Responses
	if len(resps) != toprf.Threshold {
		fmt.Println("TOPRF params are invalid")
		return false
	}

	var nodePublicKeys [toprf.Threshold]twistededwards.Point
	var evals [toprf.Threshold]twistededwards.Point
	var cs [toprf.Threshold]frontend.Variable
	var rs [toprf.Threshold]frontend.Variable
	var coeffs [toprf.Threshold]frontend.Variable

	idxs := make([]int, toprf.Threshold)
	for i := 0; i < toprf.Threshold; i++ {
		idxs[i] = int(resps[i].Index)
	}

	for i := 0; i < toprf.Threshold; i++ {
		resp := resps[i]
		nodePublicKeys[i] = utils.UnmarshalPoint(resp.PublicKeyShare)
		evals[i] = utils.UnmarshalPoint(resp.Evaluated)
		cs[i] = new(big.Int).SetBytes(resp.C)
		rs[i] = new(big.Int).SetBytes(resp.R)
		coeffs[i] = utils.Coeff(idxs[i], idxs)
	}

	witness := &chachaV3_oprf.ChachaTOPRFCircuit{
		TOPRF: toprf.Params{
			DomainSeparator: new(big.Int).SetBytes(oprf.DomainSeparator),
			Responses:       evals,
			Coefficients:    coeffs,
			SharePublicKeys: nodePublicKeys,
			C:               cs,
			R:               rs,
			Output:          new(big.Int).SetBytes(oprf.Output),
		},
	}

	// Set per-block nonce and counter from arrays
	for b := 0; b < chachaV3.Blocks; b++ {
		if b >= len(iParams.Nonces) || b >= len(iParams.Counters) {
			fmt.Printf("Invalid nonce/counter arrays length\n")
			return false
		}
		nonce := utils.BytesToUint32LEBits(iParams.Nonces[b])
		copy(witness.Nonce[b][:], nonce)
		witness.Counter[b] = utils.Uint32ToBits(iParams.Counters[b])
	}

	copy(witness.In[:], utils.BytesToUint32BEBits(iParams.Input))

	utils.SetBitmask(witness.Bitmask[:], oprf.Pos, oprf.Len)
	witness.Len = oprf.Len

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, cv.vk, wtns)
	if err != nil {
		fmt.Println(err)
	}
	return err == nil
}

type AESOPRFVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *AESOPRFVerifier) Verify(proof []byte, publicSignals []uint8) bool {
	var iParams *InputTOPRFParams
	err := json.Unmarshal(publicSignals, &iParams)
	if err != nil {
		fmt.Println(err)
		return false
	}

	oprf := iParams.TOPRF
	if oprf == nil || oprf.Responses == nil {
		fmt.Println("TOPRF params are empty")
		return false
	}

	resps := oprf.Responses
	if len(resps) != toprf.Threshold {
		fmt.Println("TOPRF params are invalid")
		return false
	}

	var nodePublicKeys [toprf.Threshold]twistededwards.Point
	var evals [toprf.Threshold]twistededwards.Point
	var cs [toprf.Threshold]frontend.Variable
	var rs [toprf.Threshold]frontend.Variable
	var coeffs [toprf.Threshold]frontend.Variable

	idxs := make([]int, toprf.Threshold)
	for i := 0; i < toprf.Threshold; i++ {
		idxs[i] = int(resps[i].Index)
	}

	for i := 0; i < toprf.Threshold; i++ {
		resp := resps[i]
		nodePublicKeys[i] = utils.UnmarshalPoint(resp.PublicKeyShare)
		evals[i] = utils.UnmarshalPoint(resp.Evaluated)
		cs[i] = new(big.Int).SetBytes(resp.C)
		rs[i] = new(big.Int).SetBytes(resp.R)
		coeffs[i] = utils.Coeff(idxs[i], idxs)
	}

	witness := &aes_v2_oprf.AESTOPRFCircuit{
		AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, 1)}, // avoid warnings
		TOPRF: toprf.Params{
			DomainSeparator: new(big.Int).SetBytes(oprf.DomainSeparator),
			Responses:       evals,
			Coefficients:    coeffs,
			SharePublicKeys: nodePublicKeys,
			C:               cs,
			R:               rs,
			Output:          new(big.Int).SetBytes(oprf.Output),
		},
	}

	// Set per-block nonce and counter from arrays
	for b := 0; b < aes_v2.BLOCKS; b++ {
		if b >= len(iParams.Nonces) || b >= len(iParams.Counters) {
			fmt.Printf("Invalid nonce/counter arrays length\n")
			return false
		}
		for i := 0; i < len(iParams.Nonces[b]); i++ {
			witness.Nonce[b][i] = iParams.Nonces[b][i]
		}
		witness.Counter[b] = iParams.Counters[b]
	}

	for i := 0; i < len(iParams.Input); i++ {
		witness.In[i] = iParams.Input[i]
	}

	utils.SetBitmask(witness.Bitmask[:], oprf.Pos, oprf.Len)
	witness.Len = oprf.Len

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, cv.vk, wtns)
	if err != nil {
		fmt.Println(err)
	}
	return err == nil
}
