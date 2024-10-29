package chacha

import (
	"crypto/rand"
	"encoding/binary"
	"gnark-symmetric-crypto/utils"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/chacha20"
)

type roundCircuit struct {
	In  [16]uints.U32
	Out [16]uints.U32 `gnark:",public"`
}

func (c *roundCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	var workingState [16]uints.U32
	copy(workingState[:], c.In[:])

	Round(uapi, &workingState)
	Serialize(uapi, &workingState)

	for i := range c.Out {
		uapi.AssertEq(c.Out[i], workingState[i])
	}

	return nil
}

type qrBlock struct {
	In  [16]uints.U32
	Out [16]uints.U32 `gnark:",public"`
}

func (c *qrBlock) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	var workingState [16]uints.U32
	copy(workingState[:], c.In[:])

	QR(uapi, &workingState, 0, 1, 2, 3)
	for i := range c.Out {
		uapi.AssertEq(c.Out[i], workingState[i])
	}
	return nil
}

func TestQR(t *testing.T) {
	assert := test.NewAssert(t)
	witness := qrBlock{}
	witness.In[0] = uints.NewU32(0x11111111)
	witness.In[1] = uints.NewU32(0x01020304)
	witness.In[2] = uints.NewU32(0x9b8d6f43)
	witness.In[3] = uints.NewU32(0x01234567)

	witness.Out[0] = uints.NewU32(0xea2a92f4)
	witness.Out[1] = uints.NewU32(0xcb1cf8ce)
	witness.Out[2] = uints.NewU32(0x4581472e)
	witness.Out[3] = uints.NewU32(0x5881c4bb)

	err := test.IsSolved(&qrBlock{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	assert.CheckCircuit(&qrBlock{}, test.WithValidAssignment(&witness))

}

func TestRound(t *testing.T) {
	assert := test.NewAssert(t)

	in := uints.NewU32Array([]uint32{
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
		0x00000001, 0x09000000, 0x4a000000, 0x00000000})

	out := utils.BytesToUint32BE([]uint8{
		0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
		0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
		0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
		0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e})

	witness := roundCircuit{}
	copy(witness.In[:], in)
	copy(witness.Out[:], out)
	err := test.IsSolved(&roundCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	assert.CheckCircuit(&roundCircuit{}, test.WithValidAssignment(&witness))
}

func TestCipher(t *testing.T) {
	assert := test.NewAssert(t)

	bKey := []uint8{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	bNonce := []uint8{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00}

	counter := uints.NewU32(1)

	bPt := make([]byte, Blocks*64)
	rand.Read(bPt)
	bCt := make([]byte, Blocks*64)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	assert.NoError(err)

	cipher.SetCounter(1)
	cipher.XORKeyStream(bCt, bPt)

	/*fmt.Println(hex.EncodeToString(bKey))
	fmt.Println(hex.EncodeToString(bNonce))
	fmt.Println(hex.EncodeToString(bPt))
	fmt.Println(hex.EncodeToString(bCt))*/

	plaintext := utils.BytesToUint32BE(bPt)
	ciphertext := utils.BytesToUint32BE(bCt)

	witness := ChaChaCircuit{}
	copy(witness.Key[:], BytesToUint32LE(bKey))
	copy(witness.Nonce[:], BytesToUint32LE(bNonce))
	witness.Counter = counter
	copy(witness.In[:], plaintext)
	copy(witness.Out[:], ciphertext)

	err = test.IsSolved(&ChaChaCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	assert.CheckCircuit(&ChaChaCircuit{}, test.WithValidAssignment(&witness))
}
func BytesToUint32LE(in []uint8) []uints.U32 {

	var res []uints.U32
	for i := 0; i < len(in); i += 4 {
		t := binary.LittleEndian.Uint32(in[i:])
		res = append(res, uints.NewU32(t))
	}
	return res
}
