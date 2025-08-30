package aes_v2_oprf

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	aes_v2 "github.com/reclaimprotocol/zk-symmetric-crypto/gnark/circuits/aesV2"
	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/circuits/toprf"
	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestAES256(t *testing.T) {

	assert := test.NewAssert(t)

	key := "F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884"
	Nonce := "00FAAC24C1585EF15A43D875"

	secretStr := "00000000001111111111000000000011" // max 62 bytes
	secretBytes := []byte(secretStr)
	d, _ := toprf.PrepareTestData(secretStr, "reclaim")

	pos := 30
	Counter := 12345
	plaintext := make([]byte, aes_v2.BLOCKS*16)
	copy(plaintext[pos:], secretBytes)

	// calculate ciphertext ourselves for each block
	block, err := aes.NewCipher(mustHex(key))
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(plaintext))
	blockSize := 16

	for b := 0; b < aes_v2.BLOCKS; b++ {
		start := b * blockSize
		end := start + blockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}

		iv := append(mustHex(Nonce), binary.BigEndian.AppendUint32(nil, uint32(Counter+b))...)
		ctr := cipher.NewCTR(block, iv)
		ctr.XORKeyStream(ciphertext[start:end], plaintext[start:end])
	}

	keyAssign := mustHex(key)
	nonceAssign := mustHex(Nonce)

	witness := createWitness256(d, keyAssign, nonceAssign, Counter, ciphertext, plaintext, pos, len(secretBytes))

	assert.CheckCircuit(&witness, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))

	r1css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())
}

func createWitness256(d *toprf.Params, bKey []uint8, bNonce []uint8, counter int, ciphertext []byte, plaintext []byte, pos, l int) AESTOPRFCircuit {
	witness := AESTOPRFCircuit{
		AESBaseCircuit: aes_v2.AESBaseCircuit{
			Key:     make([]frontend.Variable, 32),
			Counter: [aes_v2.BLOCKS]frontend.Variable{},
			Nonce:   [aes_v2.BLOCKS][12]frontend.Variable{},
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

	// Set per-block nonce and counter
	for b := 0; b < aes_v2.BLOCKS; b++ {
		for i := 0; i < len(bNonce); i++ {
			witness.Nonce[b][i] = bNonce[i]
		}
		witness.Counter[b] = counter + b
	}
	utils.SetBitmask(witness.Bitmask[:], uint32(pos), uint32(l))
	return witness
}
