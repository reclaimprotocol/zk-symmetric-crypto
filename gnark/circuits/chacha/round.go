package chacha

import (
	"github.com/consensys/gnark/std/math/uints"
)

// QR Chacha20 quarter round
func QR(uapi *uints.BinaryField[uints.U32], state *[16]uints.U32, i, j, k, l int) {

	a, b, c, d := state[i], state[j], state[k], state[l]

	a = uapi.Add(a, b)
	d = uapi.Lrot(uapi.Xor(d, a), 16)

	c = uapi.Add(c, d)
	b = uapi.Lrot(uapi.Xor(b, c), 12)

	a = uapi.Add(a, b)
	d = uapi.Lrot(uapi.Xor(d, a), 8)

	c = uapi.Add(c, d)
	b = uapi.Lrot(uapi.Xor(b, c), 7)

	state[i] = a
	state[j] = b
	state[k] = c
	state[l] = d
}

// Round performs ChaCha20 round function
func Round(uapi *uints.BinaryField[uints.U32], state *[16]uints.U32) {
	var workingState [16]uints.U32
	copy(workingState[:], state[:])
	for i := 0; i < 10; i++ {
		QR(uapi, &workingState, 0, 4, 8, 12)
		QR(uapi, &workingState, 1, 5, 9, 13)
		QR(uapi, &workingState, 2, 6, 10, 14)
		QR(uapi, &workingState, 3, 7, 11, 15)
		QR(uapi, &workingState, 0, 5, 10, 15)
		QR(uapi, &workingState, 1, 6, 11, 12)
		QR(uapi, &workingState, 2, 7, 8, 13)
		QR(uapi, &workingState, 3, 4, 9, 14)
	}

	// final step. Add initial state to working state
	for i := 0; i < 16; i++ {
		state[i] = uapi.Add(state[i], workingState[i])
	}
}

// Serialize repacks words in LE byte order
func Serialize(uapi *uints.BinaryField[uints.U32], state *[16]uints.U32) {
	for i, s := range state {
		o := uapi.UnpackLSB(s)
		state[i] = uapi.PackMSB(o...)
	}
}
