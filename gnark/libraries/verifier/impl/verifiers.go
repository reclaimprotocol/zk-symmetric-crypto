package impl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gnark-symmetric-crypto/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
)

const BITS_PER_WORD = 32
const CHACHA_BLOCKS = 1

type ChaChaCircuit struct {
	Counter [BITS_PER_WORD]frontend.Variable                     `gnark:",public"`
	Nonce   [3][BITS_PER_WORD]frontend.Variable                  `gnark:",public"`
	In      [16 * CHACHA_BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
	Out     [16 * CHACHA_BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *ChaChaCircuit) Define(_ frontend.API) error {
	return nil
}

const AES_BLOCKS = 4

type AESWrapper struct {
	Nonce      [12]frontend.Variable              `gnark:",public"`
	Counter    frontend.Variable                  `gnark:",public"`
	Plaintext  [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
	Ciphertext [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
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

	if len(publicSignals) != 128+12+4 { // plaintext, nonce, counter, ciphertext
		fmt.Printf("public signals must be 144 bytes, not %d\n", len(publicSignals))
		return false
	}

	witness := &ChaChaCircuit{}

	bct := publicSignals[:64]
	bpt := publicSignals[64+12+4:]
	bNonce := publicSignals[64 : 64+12]
	bCounter := publicSignals[64+12 : 64+12+4]

	ciphertext := utils.BytesToUint32BEBits(bct)
	plaintext := utils.BytesToUint32BEBits(bpt)

	nonce := utils.BytesToUint32LEBits(bNonce)
	counter := utils.BytesToUint32LEBits(bCounter)

	for i := 0; i < len(witness.In); i++ {
		for j := 0; j < len(witness.In[i]); j++ {
			witness.In[i][j] = plaintext[i][j]
			witness.Out[i][j] = ciphertext[i][j]
		}
	}

	for i := 0; i < len(witness.Nonce); i++ {
		for j := 0; j < len(witness.Nonce[i]); j++ {
			witness.Nonce[i][j] = nonce[i][j]
		}
	}

	for i := 0; i < len(witness.Counter); i++ {
		witness.Counter[i] = counter[0][i]
	}

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Err(err)
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
		witness.Plaintext[i] = plaintext[i]
		witness.Ciphertext[i] = ciphertext[i]
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
