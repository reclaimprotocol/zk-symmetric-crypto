package chachaV3

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

const BITS_PER_WORD = 32

func QR(api frontend.API, state *[16][BITS_PER_WORD]frontend.Variable, i, j, k, l int) {
	a, b, c, d := state[i], state[j], state[k], state[l]

	add32(api, &a, &b)
	xorRot32(api, &d, &a, 16)

	add32(api, &c, &d)
	xorRot32(api, &b, &c, 12)

	add32(api, &a, &b)
	xorRot32(api, &d, &a, 8)

	add32(api, &c, &d)
	xorRot32(api, &b, &c, 7)

	state[i] = a
	state[j] = b
	state[k] = c
	state[l] = d
}

func add32(api frontend.API, aBits, bBits *[BITS_PER_WORD]frontend.Variable) {
	a := bits.FromBinary(api, aBits[:], bits.WithNbDigits(32))
	b := bits.FromBinary(api, bBits[:], bits.WithNbDigits(32))
	res := api.Add(a, b)
	resBits := bits.ToBinary(api, res, bits.WithNbDigits(BITS_PER_WORD+1))
	for i := 0; i < BITS_PER_WORD; i++ {
		aBits[i] = resBits[i] // api.Mul(resBits[i], 1)
	}
}

func xor32(api frontend.API, a, b, c *[BITS_PER_WORD]frontend.Variable) {
	for i := 0; i < BITS_PER_WORD; i++ {
		c[i] = api.Xor(a[i], b[i])
	}
}

func xorRot32(api frontend.API, a, b *[BITS_PER_WORD]frontend.Variable, l int) {
	var res [BITS_PER_WORD]frontend.Variable
	for i := 0; i < BITS_PER_WORD; i++ {
		iRot := (i + l) % BITS_PER_WORD
		res[iRot] = api.Xor(a[i], b[i])
	}
	for i := 0; i < BITS_PER_WORD; i++ {
		a[i] = res[i] // api.Mul(res[i], 1)
	}
}

func Round(api frontend.API, state *[16][BITS_PER_WORD]frontend.Variable) {
	var workingState [16][BITS_PER_WORD]frontend.Variable
	copy(workingState[:], state[:])
	for i := 0; i < 10; i++ {
		QR(api, &workingState, 0, 4, 8, 12)
		QR(api, &workingState, 1, 5, 9, 13)
		QR(api, &workingState, 2, 6, 10, 14)
		QR(api, &workingState, 3, 7, 11, 15)
		QR(api, &workingState, 0, 5, 10, 15)
		QR(api, &workingState, 1, 6, 11, 12)
		QR(api, &workingState, 2, 7, 8, 13)
		QR(api, &workingState, 3, 4, 9, 14)
	}

	// final step. Add initial state to working state
	for i := 0; i < 16; i++ {
		add32(api, &state[i], &workingState[i])
	}

}

func repackLSB(a *[BITS_PER_WORD]frontend.Variable) {
	var res [BITS_PER_WORD]frontend.Variable
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			res[(3-i)*8+j] = a[i*8+j]
		}
	}

	for i := 0; i < BITS_PER_WORD; i++ {
		a[i] = res[i]
	}
}

// Serialize repacks words in LE byte order
func Serialize(state *[16][BITS_PER_WORD]frontend.Variable) {
	for i := range state {
		repackLSB(&state[i])
	}
}
