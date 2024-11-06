package aes_v2

import (
	"math"

	"github.com/consensys/gnark/frontend"
)

const AES_256_KEY_SIZE_BYTES = 32
const AES_256_ROUNDS = 14
const NB = 4 // columns
const AES_256_KS_WORDS = NB * (AES_256_ROUNDS + 1)

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
	xk := aes.ExpandKey(key)
	var state [16]frontend.Variable
	for i := 0; i < 16; i++ {
		state[i] = aes.VariableXor(xk[i], pt[i], 8)
	}

	var t0, t1, t2, t3 []frontend.Variable
	// iterate rounds
	for i := 1; i < 14; i++ {
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

	k := 14 * 16

	for i := 0; i < 4; i++ {
		state[i+0] = aes.VariableXor(state[i+0], xk[k+i+0], 8)
		state[i+4] = aes.VariableXor(state[i+4], xk[k+i+4], 8)
		state[i+8] = aes.VariableXor(state[i+8], xk[k+i+8], 8)
		state[i+12] = aes.VariableXor(state[i+12], xk[k+i+12], 8)
	}

	return state
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
			tt := aes.Subws(aes.sbox, t0, t1, t2, t3)
			t0, t1, t2, t3 = tt[0], tt[1], tt[2], tt[3]

			t0 = aes.VariableXor(t0, aes.RCon[i/AES_256_KEY_SIZE_BYTES], 8)
		}

		if i%AES_256_KEY_SIZE_BYTES == 16 {
			// subwords
			tt := aes.Subws(aes.sbox, t0, t1, t2, t3)
			t0, t1, t2, t3 = tt[0], tt[1], tt[2], tt[3]

		}

		expand[i] = aes.VariableXor(expand[i-AES_256_KEY_SIZE_BYTES], t0, 8)
		expand[i+1] = aes.VariableXor(expand[i-AES_256_KEY_SIZE_BYTES+1], t1, 8)
		expand[i+2] = aes.VariableXor(expand[i-AES_256_KEY_SIZE_BYTES+2], t2, 8)
		expand[i+3] = aes.VariableXor(expand[i-AES_256_KEY_SIZE_BYTES+3], t3, 8)

		i += 4
	}

	return expand
}
