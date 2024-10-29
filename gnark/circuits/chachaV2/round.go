package chachaV2

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bitslice"
)

const BITS_PER_WORD = 32

func QR(api frontend.API, state *[16]frontend.Variable, i, j, k, l int) {
	a, b, c, d := state[i], state[j], state[k], state[l]

	a = add32(api, a, b)
	d = xorRot32(api, d, a, 16)
	// d = lRot32(api, d, 16)

	c = add32(api, c, d)
	b = xorRot32(api, b, c, 12)
	// b = lRot32(api, b, 12)

	a = add32(api, a, b)
	d = xorRot32(api, d, a, 8)
	// d = lRot32(api, d, 8)

	c = add32(api, c, d)
	b = xorRot32(api, b, c, 7)
	// b = lRot32(api, b, 7)

	state[i] = a
	state[j] = b
	state[k] = c
	state[l] = d
}

func add32(api frontend.API, a, b frontend.Variable) frontend.Variable {
	a = api.Add(a, b)
	aBits := api.ToBinary(a, BITS_PER_WORD+1)
	a = api.FromBinary(aBits[:BITS_PER_WORD]...) // ditch the 33rd bit
	return a
}

func xor32(api frontend.API, a, b frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, BITS_PER_WORD)
	bBits := api.ToBinary(b, BITS_PER_WORD)

	var res frontend.Variable = 0
	for i := 0; i < BITS_PER_WORD; i++ {
		res = api.Add(api.Mul(1<<(i), api.Xor(aBits[i], bBits[i])), res)
	}

	return res
}

func xorRot32(api frontend.API, a, b frontend.Variable, l int) frontend.Variable {
	aBits := api.ToBinary(a, BITS_PER_WORD)
	bBits := api.ToBinary(b, BITS_PER_WORD)

	var res frontend.Variable = 0
	for i := 0; i < BITS_PER_WORD; i++ {

		iRot := (i + l) % BITS_PER_WORD
		res = api.Add(api.Mul(1<<(iRot), api.Xor(aBits[i], bBits[i])), res)
	}

	return res
}

func Round(api frontend.API, state *[16]frontend.Variable) {
	var workingState [16]frontend.Variable
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
		state[i] = add32(api, state[i], workingState[i])
	}

}

func repackLSB(api frontend.API, a frontend.Variable) frontend.Variable {
	lo, up := bitslice.Partition(api, a, 16, bitslice.WithNbDigits(32))

	var resBytes [4]frontend.Variable

	loLo, loUp := bitslice.Partition(api, lo, 8, bitslice.WithNbDigits(16))
	upLo, UpUp := bitslice.Partition(api, up, 8, bitslice.WithNbDigits(16))

	resBytes[0] = UpUp
	resBytes[1] = upLo
	resBytes[2] = loUp
	resBytes[3] = loLo

	var ret frontend.Variable = 0

	for i := range resBytes {
		ret = api.Add(ret, api.Mul(1<<(8*i), resBytes[i]))
	}
	return ret
}

// Serialize repacks words in LE byte order
func Serialize(api frontend.API, state *[16]frontend.Variable) {
	for i := range state {
		state[i] = repackLSB(api, state[i])
	}
}
