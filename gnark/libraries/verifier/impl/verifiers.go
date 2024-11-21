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
	pubLen := chunkLen*2 + 12 + 4     // in & out, nonce, counter
	if len(publicSignals) != pubLen { // in, nonce, counter, out
		fmt.Printf("public signals must be %d bytes, not %d\n", pubLen, len(publicSignals))
		return false
	}

	witness := &chachaV3.ChaChaCircuit{}

	bOut := publicSignals[:chunkLen]
	bIn := publicSignals[chunkLen+12+4:]
	bNonce := publicSignals[chunkLen : chunkLen+12]
	bCounter := publicSignals[chunkLen+12 : chunkLen+12+4]

	out := utils.BytesToUint32BEBits(bOut)
	in := utils.BytesToUint32BEBits(bIn)
	nonce := utils.BytesToUint32LEBits(bNonce)
	counter := utils.BytesToUint32LEBits(bCounter)

	copy(witness.In[:], in)
	copy(witness.Out[:], out)
	copy(witness.Nonce[:], nonce)
	witness.Counter = counter[0]

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

	if len(publicSignals) != bytesPerInput*2+12+4 { // plaintext, nonce, counter, ciphertext
		return false
	}

	ciphertext := publicSignals[:bytesPerInput]
	plaintext := publicSignals[bytesPerInput+12+4:]
	nonce := publicSignals[bytesPerInput : bytesPerInput+12]
	bCounter := publicSignals[bytesPerInput+12 : bytesPerInput+12+4]

	witness := &aes_v2.AESCircuit{
		AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, 1)}, // avoid warnings
	}

	for i := 0; i < len(plaintext); i++ {
		witness.In[i] = plaintext[i]
		witness.Out[i] = ciphertext[i]
	}

	for i := 0; i < len(nonce); i++ {
		witness.Nonce[i] = nonce[i]
	}

	witness.Counter = binary.BigEndian.Uint32(bCounter)

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

	nonce := utils.BytesToUint32LEBits(iParams.Nonce)
	counter := utils.Uint32ToBits(iParams.Counter)

	copy(witness.In[:], utils.BytesToUint32BEBits(iParams.Input))
	copy(witness.Nonce[:], nonce)
	witness.Counter = counter

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

	for i := 0; i < len(iParams.Nonce); i++ {
		witness.Nonce[i] = iParams.Nonce[i]
	}
	for i := 0; i < len(iParams.Input); i++ {
		witness.In[i] = iParams.Input[i]
	}

	witness.Counter = iParams.Counter

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
