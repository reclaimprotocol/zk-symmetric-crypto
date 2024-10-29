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
	expandedKey := aes.ExpandKey(key)

	var state [16]frontend.Variable
	var i = 0
	for k := 0; k < 4; k++ {
		state[0+k] = pt[i]
		state[4+k] = pt[i+1]
		state[8+k] = pt[i+2]
		state[12+k] = pt[i+3]
		i += 4
	}
	state = aes.AddRoundKey(state, expandedKey[:], 0)

	// iterate rounds
	i = 1
	for ; i < 10; i++ {
		state = aes.SubBytes(state)
		state = aes.ShiftRows(state)
		state = aes.MixColumns(state)
		state = aes.AddRoundKey2(state, expandedKey[:], i*4*4)
	}

	state = aes.SubBytes(state)
	state = aes.ShiftRows(state)
	state = aes.AddRoundKey2(state, expandedKey[:], 10*4*4)

	var out [16]frontend.Variable
	ctr := 0
	for i := 0; i < 4; i++ {
		out[ctr] = state[i]
		out[ctr+1] = state[4+i]
		out[ctr+2] = state[8+i]
		out[ctr+3] = state[12+i]
		ctr += 4
	}

	return out
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

			// subwords
			t0 = aes.Subw(aes.sbox0, t0)
			t1 = aes.Subw(aes.sbox0, t1)
			t2 = aes.Subw(aes.sbox0, t2)
			t3 = aes.Subw(aes.sbox0, t3)
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
