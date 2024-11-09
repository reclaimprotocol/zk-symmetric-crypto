package chachaV3_oprf

import (
	"crypto/rand"
	"fmt"
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

type qrBlock struct {
	In  [16][BITS_PER_WORD]frontend.Variable
	Out [16][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *qrBlock) Define(api frontend.API) error {

	a0 := api.ToBinary(0x11111111)
	a1 := api.ToBinary(0x01020304)
	a2 := api.ToBinary(0x9b8d6f43)
	a3 := api.ToBinary(0x01234567)

	b0 := api.ToBinary(0xea2a92f4)
	b1 := api.ToBinary(0xcb1cf8ce)
	b2 := api.ToBinary(0x4581472e)
	b3 := api.ToBinary(0x5881c4bb)

	for i := 0; i < BITS_PER_WORD; i++ {
		c.In[0][i] = a0[i]
		c.In[1][i] = a1[i]
		c.In[2][i] = a2[i]
		c.In[3][i] = a3[i]

		c.Out[0][i] = b0[i]
		c.Out[1][i] = b1[i]
		c.Out[2][i] = b2[i]
		c.Out[3][i] = b3[i]
	}

	QR(api, &c.In, 0, 1, 2, 3)
	for i := range c.Out {
		a := api.FromBinary(c.In[i][:]...)
		b := api.FromBinary(c.Out[i][:]...)
		api.AssertIsEqual(a, b)

	}
	return nil
}

func TestQR(t *testing.T) {
	assert := test.NewAssert(t)
	witness := qrBlock{}
	for i := 0; i < 16; i++ {
		witness.In[i] = [BITS_PER_WORD]frontend.Variable{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		witness.Out[i] = [BITS_PER_WORD]frontend.Variable{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	}

	err := test.IsSolved(&qrBlock{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	assert.CheckCircuit(&qrBlock{}, test.WithValidAssignment(&witness))

}

type roundCircuit struct {
	In  [16][BITS_PER_WORD]frontend.Variable
	Out [16][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *roundCircuit) Define(api frontend.API) error {

	var workingState [16][BITS_PER_WORD]frontend.Variable
	copy(workingState[:], c.In[:])

	Round(api, &workingState)
	Serialize(&workingState)

	for i := range c.Out {

		a := api.FromBinary(c.Out[i][:]...)
		b := api.FromBinary(workingState[i][:]...)
		api.AssertIsEqual(a, b)
	}

	return nil
}

func TestRound(t *testing.T) {
	assert := test.NewAssert(t)

	in := []frontend.Variable{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
		0x00000001, 0x09000000, 0x4a000000, 0x00000000}

	out := utils.BytesToUint32BERaw([]uint8{
		0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
		0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
		0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
		0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e})

	witness := roundCircuit{}

	for i := 0; i < len(in); i++ {
		a := utils.Uint32ToBits(in[i])
		b := utils.Uint32ToBits(out[i])
		copy(witness.In[i][:], a[:])
		copy(witness.Out[i][:], b[:])
	}
	err := test.IsSolved(&roundCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	assert.CheckCircuit(&roundCircuit{}, test.WithValidAssignment(&witness))
}

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
	plaintext := make([]byte, Blocks*64)
	copy(plaintext[pos:], secretBytes)

	ciphertext := make([]byte, Blocks*64)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	assert.NoError(err)

	cipher.SetCounter(uint32(counter))
	cipher.XORKeyStream(ciphertext, plaintext)

	d, err := toprf.PrepareTestData(secretStr, "reclaim")
	assert.NoError(err)

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

func createWitness(d *toprf.TOPRFParams, bKey []uint8, bNonce []uint8, counter int, ciphertext []byte, plaintext []byte, pos, len int) ChachaTOPRFCircuit {
	witness := ChachaTOPRFCircuit{
		Len: len,
		TOPRF: TOPRFData{
			Mask:              d.Mask,
			DomainSeparator:   d.DomainSeparator,
			EvaluatedElements: d.Responses,
			Coefficients:      d.Coefficients,
			Output:            d.Output,
			PublicKeys:        d.SharePublicKeys,
			C:                 d.C,
			R:                 d.R,
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
