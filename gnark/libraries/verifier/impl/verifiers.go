package impl

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
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

const AES_BLOCKS = 4

type AESWrapper struct {
	Nonce   [12]frontend.Variable              `gnark:",public"`
	Counter frontend.Variable                  `gnark:",public"`
	In      [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
	Out     [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
}

func (circuit *AESWrapper) Define(_ frontend.API) error {
	return nil
}

type Verifier interface {
	Verify(proof []byte, publicSignals []uint8) bool
}

type ChachaVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaVerifier) Verify(proof []byte, publicSignals []uint8) bool {

	if len(publicSignals) != 128+12+4 { // in, nonce, counter, out
		fmt.Printf("public signals must be 144 bytes, not %d\n", len(publicSignals))
		return false
	}

	witness := &chachaV3.ChaChaCircuit{}

	bOut := publicSignals[:64]
	bIn := publicSignals[64+12+4:]
	bNonce := publicSignals[64 : 64+12]
	bCounter := publicSignals[64+12 : 64+12+4]

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

	if len(publicSignals) != 128+12+4 { // plaintext, nonce, counter, ciphertext
		return false
	}

	ciphertext := publicSignals[:64]
	plaintext := publicSignals[64+12+4:]
	nonce := publicSignals[64 : 64+12]
	bCounter := publicSignals[64+12 : 64+12+4]

	witness := &AESWrapper{}

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
	var iParams *InputChachaTOPRFParams
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
		nodePublicKeys[i] = utils.UnmarshalPoint(resp.PublicKey)
		evals[i] = utils.UnmarshalPoint(resp.Evaluated)
		cs[i] = new(big.Int).SetBytes(resp.C)
		rs[i] = new(big.Int).SetBytes(resp.R)
		coeffs[i] = utils.Coeff(idxs[i], idxs)
	}

	witness := &chachaV3_oprf.ChachaTOPRFCircuit{
		TOPRF: chachaV3_oprf.TOPRFData{
			DomainSeparator:   new(big.Int).SetBytes(oprf.DomainSeparator),
			EvaluatedElements: evals,
			Coefficients:      coeffs,
			PublicKeys:        nodePublicKeys,
			C:                 cs,
			R:                 rs,
			Output:            new(big.Int).SetBytes(oprf.Output),
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
