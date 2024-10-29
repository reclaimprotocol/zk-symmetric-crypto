package aes

import (
	"math"

	"github.com/consensys/gnark/frontend"
)

const AES_256_KEY_SIZE_BYTES = 32
const AES_256_ROUNDS = 14
const NB = 4 // columns
const AES_256_KS_WORDS = NB * (AES_256_ROUNDS + 1)

const BLOCKS = 1

type AES256Wrapper struct {
	AESWrapper
}

func (circuit *AES256Wrapper) Define(api frontend.API) error {
	// init aes gadget
	aes := NewAES256(api)
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

type AES256 struct {
	AESGadget
	api frontend.API
}

// retuns AES256 instance which can be used inside a circuit
func NewAES256(api frontend.API) AES256 {
	return AES256{api: api, AESGadget: NewAESGadget(api)}
}

// AES256 encrypt function
func (aes *AES256) Encrypt(key []frontend.Variable, pt [16]frontend.Variable) [16]frontend.Variable {

	// expand key
	expandedKey := aes.ExpandKey(key)

	var state [16]frontend.Variable
	var i = 0
	for k := 0; k < 4; k++ {
		state[0+k] = pt[i+0]
		state[4+k] = pt[i+1]
		state[8+k] = pt[i+2]
		state[12+k] = pt[i+3]
		i += 4
	}
	state = aes.AddRoundKey(state, expandedKey[:], 0)

	// iterate rounds
	i = 1
	for ; i < AES_256_ROUNDS; i++ {
		state = aes.SubBytes(state)
		state = aes.ShiftRows(state)
		state = aes.MixColumns(state)
		state = aes.AddRoundKey2(state, expandedKey[:], i*4*4)
	}

	state = aes.SubBytes(state)
	state = aes.ShiftRows(state)
	state = aes.AddRoundKey2(state, expandedKey[:], AES_256_ROUNDS*4*4)

	var out [16]frontend.Variable
	ctr := 0
	for i := 0; i < 4; i++ {
		out[ctr+0] = state[i+0]
		out[ctr+1] = state[4+i]
		out[ctr+2] = state[8+i]
		out[ctr+3] = state[12+i]
		ctr += 4
	}

	return out
}

// expands 16 byte key to 240 byte output
func (aes *AES256) ExpandKey(key []frontend.Variable) [AES_256_KS_WORDS * 4]frontend.Variable {

	var expand [AES_256_KS_WORDS * 4]frontend.Variable
	i := 0

	for i < AES_256_KEY_SIZE_BYTES {
		expand[i] = key[i]
		expand[i+1] = key[i+1]
		expand[i+2] = key[i+2]
		expand[i+3] = key[i+3]

		i += 4
	}

	for i < (AES_256_KS_WORDS * 4) {
		t0 := expand[i-4]
		t1 := expand[i-3]
		t2 := expand[i-2]
		t3 := expand[i-1]

		if i%AES_256_KEY_SIZE_BYTES == 0 {
			// rotation
			t0, t1, t2, t3 = t1, t2, t3, t0

			// subwords
			t0 = aes.Subw(aes.sbox0, t0)
			t1 = aes.Subw(aes.sbox0, t1)
			t2 = aes.Subw(aes.sbox0, t2)
			t3 = aes.Subw(aes.sbox0, t3)

			t0 = aes.VariableXor(t0, aes.RCon[i/AES_256_KEY_SIZE_BYTES], 8)
		}

		if i%AES_256_KEY_SIZE_BYTES == 16 {
			// subwords
			t0 = aes.Subw(aes.sbox0, t0)
			t1 = aes.Subw(aes.sbox0, t1)
			t2 = aes.Subw(aes.sbox0, t2)
			t3 = aes.Subw(aes.sbox0, t3)

		}

		expand[i] = aes.VariableXor(expand[i-AES_256_KEY_SIZE_BYTES], t0, 8)
		expand[i+1] = aes.VariableXor(expand[i-AES_256_KEY_SIZE_BYTES+1], t1, 8)
		expand[i+2] = aes.VariableXor(expand[i-AES_256_KEY_SIZE_BYTES+2], t2, 8)
		expand[i+3] = aes.VariableXor(expand[i-AES_256_KEY_SIZE_BYTES+3], t3, 8)

		i += 4
	}

	return expand
}
