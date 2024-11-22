package aes_v2_oprf

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	"gnark-symmetric-crypto/circuits/toprf"
	"gnark-symmetric-crypto/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestAES128(t *testing.T) {
	assert := test.NewAssert(t)

	key := mustHex("7E24067817FAE0D743D6CE1F32539163")
	Nonce := "006CB6DBC0543B59DA48D90B"

	secretStr := "00000000001111111111000000000011000000000011111111110000000000" // max 62 bytes
	secretBytes := []byte(secretStr)
	d, _ := toprf.PrepareTestData(secretStr, "reclaim")

	pos := 18
	Counter := 12345
	plaintext := make([]byte, aes_v2.BLOCKS*16)
	copy(plaintext[pos:], secretBytes)

	// calculate ciphertext ourselves
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ctr := cipher.NewCTR(block, append(mustHex(Nonce), binary.BigEndian.AppendUint32(nil, uint32(Counter))...))
	ciphertext := make([]byte, len(plaintext))
	ctr.XORKeyStream(ciphertext, plaintext)

	nonceAssign := mustHex(Nonce)

	witness := createWitness(d, key, nonceAssign, Counter, ciphertext, plaintext, pos, len(secretBytes))

	vKey := make([]frontend.Variable, len(key))
	for i := 0; i < len(vKey); i++ {
		vKey[i] = key[i]
	}
	assert.CheckCircuit(&witness, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))

	r1css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func createWitness(d *toprf.Params, bKey []uint8, bNonce []uint8, counter int, ciphertext []byte, plaintext []byte, pos, l int) AESTOPRFCircuit {
	witness := AESTOPRFCircuit{
		AESBaseCircuit: aes_v2.AESBaseCircuit{
			Key:     make([]frontend.Variable, 16),
			Counter: counter,
			Nonce:   [12]frontend.Variable{},
			In:      [aes_v2.BLOCKS * 16]frontend.Variable{},
		},
		Out: [aes_v2.BLOCKS * 16]frontend.Variable{},
		Len: l,
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

	for i := 0; i < len(bKey); i++ {
		witness.Key[i] = bKey[i]
	}
	for i := 0; i < len(ciphertext); i++ {
		witness.In[i] = ciphertext[i]
	}
	for i := 0; i < len(plaintext); i++ {
		witness.Out[i] = plaintext[i]
	}

	for i := 0; i < len(bNonce); i++ {
		witness.Nonce[i] = bNonce[i]
	}
	utils.SetBitmask(witness.Bitmask[:], uint32(pos), uint32(l))
	return witness
}
