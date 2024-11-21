package aes_v2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestAES256(t *testing.T) {

	assert := test.NewAssert(t)

	key := "F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884"
	plaintext := "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A0A0B0C0D0E0F101112131415161718191B1C1D1E1F"
	// ciphertext := "F05E231B3894612C49EE000B804EB2A9B8306B508F839D6A5530831D9344AF1C"
	Nonce := "00FAAC24C1585EF15A43D875"
	Counter := 1

	// calculate ciphertext ourselves
	block, err := aes.NewCipher(mustHex(key))
	if err != nil {
		panic(err)
	}
	ctr := cipher.NewCTR(block, append(mustHex(Nonce), binary.BigEndian.AppendUint32(nil, uint32(Counter))...))
	ciphertext := make([]byte, len(mustHex(plaintext)))
	ctr.XORKeyStream(ciphertext, mustHex(plaintext))

	keyAssign := StrToIntSlice(key, true)
	ptAssign := StrToIntSlice(plaintext, true)
	// ctAssign := StrToIntSlice(ciphertext, true)
	nonceAssign := StrToIntSlice(Nonce, true)

	// witness values preparation
	assignment := AESCircuit{
		AESBaseCircuit: AESBaseCircuit{
			Key:     make([]frontend.Variable, 32),
			Counter: Counter,
			Nonce:   [12]frontend.Variable{},
			In:      [BLOCKS * 16]frontend.Variable{},
		},
		Out: [BLOCKS * 16]frontend.Variable{},
	}

	// assign values here because required to use make in assignment
	for i := 0; i < len(keyAssign); i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < len(ptAssign); i++ {
		assignment.In[i] = ptAssign[i]
	}
	for i := 0; i < len(ciphertext); i++ {
		assignment.Out[i] = ciphertext[i]
	}

	for i := 0; i < len(nonceAssign); i++ {
		assignment.Nonce[i] = nonceAssign[i]
	}

	assert.CheckCircuit(&AESCircuit{
		AESBaseCircuit: AESBaseCircuit{
			Key:     make([]frontend.Variable, 32),
			Counter: Counter,
			Nonce:   [12]frontend.Variable{},
			In:      [BLOCKS * 16]frontend.Variable{},
		},
		Out: [BLOCKS * 16]frontend.Variable{},
	}, test.WithValidAssignment(&assignment))
}

func TestCompile256(t *testing.T) {
	curve := ecc.BN254.ScalarField()

	witness := AESCircuit{
		AESBaseCircuit: AESBaseCircuit{
			Key: make([]frontend.Variable, 32),
		},
	}

	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())
}
