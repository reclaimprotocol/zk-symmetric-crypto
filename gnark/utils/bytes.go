package utils

import (
	"encoding/binary"
	"math/big"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func BytesToUint32BEBits(in []uint8) [][32]frontend.Variable {

	var res []uint32
	for i := 0; i < len(in); i += 4 {
		t := binary.BigEndian.Uint32(in[i:])
		res = append(res, t)
	}
	return uintsToBits(res)
}

func BytesToUint32LEBits(in []uint8) [][32]frontend.Variable {

	var res []uint32
	for i := 0; i < len(in); i += 4 {
		t := binary.LittleEndian.Uint32(in[i:])
		res = append(res, t)
	}
	return uintsToBits(res)
}

func Uint32ToBits(in frontend.Variable) [32]frontend.Variable {
	var b *big.Int
	switch it := in.(type) {
	case uint32:
		b = big.NewInt(int64(it))
	case int:
		b = big.NewInt(int64(it))
	default:
		panic("invalid type")
	}

	var res [32]frontend.Variable
	for i := 0; i < 32; i++ {
		res[i] = b.Bit(i)
	}
	return res
}

func uintsToBits(in []uint32) [][32]frontend.Variable {
	res := make([][32]frontend.Variable, len(in))
	for i := 0; i < len(in); i++ {
		res[i] = Uint32ToBits(in[i])
	}
	return res
}

func BytesToUint32BERaw(in []uint8) []frontend.Variable {

	var res []frontend.Variable
	for i := 0; i < len(in); i += 4 {
		t := binary.BigEndian.Uint32(in[i:])
		res = append(res, t)
	}
	return res
}

func UnmarshalPoint(b []byte) twistededwards.Point {

	point := &tbn254.PointAffine{}
	err := point.Unmarshal(b)
	if err != nil {
		panic(err)
	}

	return twistededwards.Point{
		X: point.X.BigInt(&big.Int{}),
		Y: point.Y.BigInt(&big.Int{}),
	}
}
