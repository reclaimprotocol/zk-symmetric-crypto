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

package aes

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestAES256(t *testing.T) {

	assert := test.NewAssert(t)

	key := "F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884"
	plaintext := "000102030405060708090A0B0C0D0E0F"  // + "101112131415161718191A1B1C1D1E1F"
	ciphertext := "F05E231B3894612C49EE000B804EB2A9" // + "B8306B508F839D6A5530831D9344AF1C"
	Nonce := "00FAAC24C1585EF15A43D875"
	Counter := 1

	keyAssign := StrToIntSlice(key, true)
	ptAssign := StrToIntSlice(plaintext, true)
	ctAssign := StrToIntSlice(ciphertext, true)
	nonceAssign := StrToIntSlice(Nonce, true)

	// witness values preparation
	assignment := AES256Wrapper{
		AESWrapper{
			Key:        make([]frontend.Variable, 32),
			Counter:    Counter,
			Nonce:      [12]frontend.Variable{},
			Plaintext:  [16]frontend.Variable{},
			Ciphertext: [16]frontend.Variable{},
		},
	}

	// assign values here because required to use make in assignment
	for i := 0; i < len(keyAssign); i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < len(ptAssign); i++ {
		assignment.Plaintext[i] = ptAssign[i]
	}
	for i := 0; i < len(ctAssign); i++ {
		assignment.Ciphertext[i] = ctAssign[i]
	}

	for i := 0; i < len(nonceAssign); i++ {
		assignment.Nonce[i] = nonceAssign[i]
	}

	assert.CheckCircuit(&AES256Wrapper{
		AESWrapper{
			Key:        make([]frontend.Variable, 32),
			Counter:    Counter,
			Nonce:      [12]frontend.Variable{},
			Plaintext:  [16]frontend.Variable{},
			Ciphertext: [16]frontend.Variable{},
		},
	}, test.WithValidAssignment(&assignment))
}
