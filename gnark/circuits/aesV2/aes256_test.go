/*
Copyright © 2023 Jan Lauinger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
	plaintext := "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
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
	assignment := AES256Wrapper{
		AESWrapper{
			Key:        make([]frontend.Variable, 32),
			Counter:    Counter,
			Nonce:      [12]frontend.Variable{},
			Plaintext:  [BLOCKS * 16]frontend.Variable{},
			Ciphertext: [BLOCKS * 16]frontend.Variable{},
		},
	}

	// assign values here because required to use make in assignment
	for i := 0; i < len(keyAssign); i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < len(ptAssign); i++ {
		assignment.Plaintext[i] = ptAssign[i]
	}
	for i := 0; i < len(ciphertext); i++ {
		assignment.Ciphertext[i] = ciphertext[i]
	}

	for i := 0; i < len(nonceAssign); i++ {
		assignment.Nonce[i] = nonceAssign[i]
	}

	assert.CheckCircuit(&AES256Wrapper{
		AESWrapper{
			Key:        make([]frontend.Variable, 32),
			Counter:    Counter,
			Nonce:      [12]frontend.Variable{},
			Plaintext:  [BLOCKS * 16]frontend.Variable{},
			Ciphertext: [BLOCKS * 16]frontend.Variable{},
		},
	}, test.WithValidAssignment(&assignment))
}

func TestCompile256(t *testing.T) {
	curve := ecc.BN254.ScalarField()

	witness := AES256Wrapper{
		AESWrapper: AESWrapper{
			Key: make([]frontend.Variable, 32),
		},
	}

	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())
}
