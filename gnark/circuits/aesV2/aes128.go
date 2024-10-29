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
	"math"

	"github.com/consensys/gnark/frontend"
)

type AES128Wrapper struct {
	AESWrapper
}

func (circuit *AES128Wrapper) Define(api frontend.API) error {

	// init aes gadget
	aes := NewAES128(api)
	counter := circuit.Counter

	var counterBlock [16]frontend.Variable

	for i := 0; i < 12; i++ {
		counterBlock[i] = circuit.Nonce[i]
	}

	for b := 0; b < BLOCKS; b++ {
		aes.createIV(counter, counterBlock[:])
		// encrypt counter under key

		keystream := aes.Encrypt(circuit.Key, counterBlock)

		for i := 0; i < 16; i++ {
			api.AssertIsEqual(circuit.Ciphertext[b*16+i], aes.VariableXor(keystream[i], circuit.Plaintext[b*16+i], 8))
		}
		counter = api.Add(counter, 1)
		api.AssertIsLessOrEqual(counter, math.MaxUint32)
	}
	api.AssertIsEqual(counter, api.Add(circuit.Counter, BLOCKS))
	return nil
}

type AES128 struct {
	AESGadget
	api frontend.API
}

// retuns AES128 instance which can be used inside a circuit
func NewAES128(api frontend.API) AES128 {
	return AES128{api: api, AESGadget: NewAESGadget(api)}
}

// aes128 encrypt function
func (aes *AES128) Encrypt(key []frontend.Variable, pt [16]frontend.Variable) [16]frontend.Variable {
	// expand key
	xk := aes.ExpandKey(key)
	var state [16]frontend.Variable
	for i := 0; i < 16; i++ {
		state[i] = aes.VariableXor(xk[i], pt[i], 8)
	}

	var t0, t1, t2, t3 []frontend.Variable
	// iterate rounds
	for i := 1; i < 10; i++ {
		k := i * 16
		t0 = aes.XorSubWords(state[0], state[5], state[10], state[15], xk[k+0:k+4])
		t1 = aes.XorSubWords(state[4], state[9], state[14], state[3], xk[k+4:k+8])
		t2 = aes.XorSubWords(state[8], state[13], state[2], state[7], xk[k+8:k+12])
		t3 = aes.XorSubWords(state[12], state[1], state[6], state[11], xk[k+12:k+16])

		copy(state[:4], t0)
		copy(state[4:8], t1)
		copy(state[8:12], t2)
		copy(state[12:16], t3)
	}

	copy(state[:], aes.ShiftSub(state))

	k := 10 * 16

	for i := 0; i < 4; i++ {
		state[i+0] = aes.VariableXor(state[i+0], xk[k+i+0], 8)
		state[i+4] = aes.VariableXor(state[i+4], xk[k+i+4], 8)
		state[i+8] = aes.VariableXor(state[i+8], xk[k+i+8], 8)
		state[i+12] = aes.VariableXor(state[i+12], xk[k+i+12], 8)
	}

	return state
}

// expands 16 byte key to 176 byte output
func (aes *AES128) ExpandKey(key []frontend.Variable) [176]frontend.Variable {

	var expand [176]frontend.Variable
	i := 0

	for i < 16 {
		expand[i] = key[i]
		expand[i+1] = key[i+1]
		expand[i+2] = key[i+2]
		expand[i+3] = key[i+3]

		i += 4
	}

	for i < 176 {
		t0 := expand[i-4]
		t1 := expand[i-3]
		t2 := expand[i-2]
		t3 := expand[i-1]

		if i%16 == 0 {
			// t = subw(rotw(t)) ^ (uint32(powx[i/nb-1]) << 24)

			// rotation
			t0, t1, t2, t3 = t1, t2, t3, t0

			// sub words
			tt := aes.Subws(aes.sbox, t0, t1, t2, t3)
			t0, t1, t2, t3 = tt[0], tt[1], tt[2], tt[3]

			t0 = aes.VariableXor(t0, aes.RCon[i/16], 8)
		}

		expand[i] = aes.VariableXor(expand[i-16], t0, 8)
		expand[i+1] = aes.VariableXor(expand[i-16+1], t1, 8)
		expand[i+2] = aes.VariableXor(expand[i-16+2], t2, 8)
		expand[i+3] = aes.VariableXor(expand[i-16+3], t3, 8)

		i += 4
	}

	return expand
}
