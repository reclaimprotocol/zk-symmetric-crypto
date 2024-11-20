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

package aes_v2_oprf

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"gnark-symmetric-crypto/circuits/toprf"
	"gnark-symmetric-crypto/utils"
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
	d, err := toprf.PrepareTestData(secretStr, "reclaim")
	assert.NoError(err)

	pos := 30
	Counter := 12345
	plaintext := make([]byte, BLOCKS*16)
	copy(plaintext[pos:], secretBytes)

	// calculate ciphertext ourselves
	block, err := aes.NewCipher(mustHex(key))
	if err != nil {
		panic(err)
	}
	ctr := cipher.NewCTR(block, append(mustHex(Nonce), binary.BigEndian.AppendUint32(nil, uint32(Counter))...))
	ciphertext := make([]byte, len(plaintext))
	ctr.XORKeyStream(ciphertext, plaintext)

	keyAssign := mustHex(key)
	nonceAssign := mustHex(Nonce)

	witness := createWitness256(d, keyAssign, nonceAssign, Counter, ciphertext, plaintext, pos, len(secretBytes))

	assert.CheckCircuit(&AES256Wrapper{
		AESWrapper{
			Key:     make([]frontend.Variable, 32),
			Counter: Counter,
			Nonce:   [12]frontend.Variable{},
			In:      [BLOCKS * 16]frontend.Variable{},
			Out:     [BLOCKS * 16]frontend.Variable{},
		},
	}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))

	r1css, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())
}

func createWitness256(d *toprf.TOPRFParams, bKey []uint8, bNonce []uint8, counter int, ciphertext []byte, plaintext []byte, pos, l int) AES256Wrapper {
	witness := AES256Wrapper{

		AESWrapper{
			Key:     make([]frontend.Variable, 32),
			Nonce:   [12]frontend.Variable{},
			Counter: counter,
			In:      [BLOCKS * 16]frontend.Variable{},
			Out:     [BLOCKS * 16]frontend.Variable{},
			Len:     l,
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
