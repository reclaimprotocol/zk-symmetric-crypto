package chachaV3_oprf

import (
	"crypto/rand"
	"fmt"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/circuits/toprf"
	"gnark-symmetric-crypto/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/chacha20"
)

func TestCipher(t *testing.T) {
	assert := test.NewAssert(t)

	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)
	rand.Read(bKey)
	rand.Read(bNonce)

	secretStr := "00000000001111111111000000000011" // max 62 bytes
	secretBytes := []byte(secretStr)

	pos := 128 - 62
	counter := 12345
	plaintext := make([]byte, chachaV3.Blocks*64)
	copy(plaintext[pos:], secretBytes)

	ciphertext := make([]byte, chachaV3.Blocks*64)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	assert.NoError(err)

	cipher.SetCounter(uint32(counter))
	cipher.XORKeyStream(ciphertext, plaintext)

	d, _ := toprf.PrepareTestData(secretStr, "reclaim")

	witness := createWitness(d, bKey, bNonce, counter, ciphertext, plaintext, pos, len(secretBytes))

	err = test.IsSolved(&witness, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	assert.CheckCircuit(&witness, test.WithValidAssignment(&witness), test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &ChachaTOPRFCircuit{})
	assert.NoError(err)
	fmt.Println(cs.GetNbConstraints(), cs.GetNbPublicVariables(), cs.GetNbSecretVariables())

	pk, vk, err := groth16.Setup(cs)
	assert.NoError(err)

	witness = createWitness(d, bKey, bNonce, counter, ciphertext, plaintext, pos, len(secretBytes))
	wtns, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	proof, err := groth16.Prove(cs, pk, wtns)
	assert.NoError(err)

	wPub, err := wtns.Public()
	assert.NoError(err)
	err = groth16.Verify(proof, vk, wPub)
	assert.NoError(err)
}

func createWitness(d *toprf.Params, bKey []uint8, bNonce []uint8, counter int, ciphertext []byte, plaintext []byte, pos, len int) ChachaTOPRFCircuit {
	witness := ChachaTOPRFCircuit{
		Len: len,
		TOPRF: toprf.Params{
			Mask:            d.Mask,
			DomainSeparator: d.DomainSeparator,
			Responses:       d.Responses,
			Coefficients:    d.Coefficients,
			Output:          d.Output,
			SharePublicKeys: d.SharePublicKeys,
			C:               d.C,
			R:               d.R,
		},
	}

	copy(witness.Key[:], utils.BytesToUint32LEBits(bKey))
	copy(witness.Nonce[:], utils.BytesToUint32LEBits(bNonce))
	witness.Counter = utils.Uint32ToBits(counter)
	copy(witness.In[:], utils.BytesToUint32BEBits(ciphertext))
	copy(witness.Out[:], utils.BytesToUint32BEBits(plaintext))
	utils.SetBitmask(witness.Bitmask[:], uint32(pos), uint32(len))
	return witness
}
