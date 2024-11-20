package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	tbn "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

var TNBCurveOrder = func() *big.Int { order := twistededwards.GetEdwardsCurve().Order; return &order }()

type OPRFRequest struct {
	Mask           *big.Int `json:"mask"`
	MaskedData     *twistededwards.PointAffine
	SecretElements [2]*big.Int
}

type OPRFResponse struct {
	EvaluatedPoint *twistededwards.PointAffine
	C              *big.Int
	R              *big.Int
}

func OPRFGenerateRequest(secretBytes []byte, domainSeparator string) (*OPRFRequest, error) {
	if len(secretBytes) > 31*2 {
		return nil, errors.New("secret data too big")
	}
	domainBytes := []byte(domainSeparator)
	if len(domainBytes) > 31 {
		return nil, errors.New("domain separator too big")
	}

	var secretElements [2]*big.Int

	if len(secretBytes) > 31 {
		secretElements[0] = new(big.Int).SetBytes(BEtoLE(secretBytes[:31]))
		secretElements[1] = new(big.Int).SetBytes(BEtoLE(secretBytes[31:]))
	} else {
		secretElements[0] = new(big.Int).SetBytes(BEtoLE(secretBytes))
		secretElements[1] = big.NewInt(0)
	}

	H := HashToCurve(secretElements[0].Bytes(), secretElements[1].Bytes(), domainBytes) // H
	if !H.IsOnCurve() {
		return nil, fmt.Errorf("point is not on curve")
	}

	// random mask
	mask, err := rand.Int(rand.Reader, TNBCurveOrder)
	if err != nil {
		return nil, err
	}

	masked := &twistededwards.PointAffine{}
	masked.ScalarMultiplication(H, mask) // H*mask

	return &OPRFRequest{
		Mask:           mask,
		MaskedData:     masked,
		SecretElements: secretElements,
	}, nil
}

func OPRFEvaluate(serverPrivate *big.Int, request *twistededwards.PointAffine) (*OPRFResponse, error) {
	curve := twistededwards.GetEdwardsCurve()

	t := new(twistededwards.PointAffine)
	t.Set(request)
	t.ScalarMultiplication(t, big.NewInt(8)) // cofactor check

	if !t.IsOnCurve() {
		return nil, fmt.Errorf("request point is not on curve")
	}

	resp := &twistededwards.PointAffine{}
	resp.ScalarMultiplication(request, serverPrivate) // H*mask*sk

	serverPublic := &twistededwards.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, serverPrivate) // G*sk

	c, r, err := ProveDLEQ(serverPrivate, request)
	if err != nil {
		return nil, err
	}
	return &OPRFResponse{
		EvaluatedPoint: resp,
		C:              c,
		R:              r,
	}, nil
}

func OPRFFinalize(serverPublic *twistededwards.PointAffine, request *OPRFRequest, response *OPRFResponse) (*big.Int, error) {
	if !VerifyDLEQ(response.C, response.R, serverPublic, response.EvaluatedPoint, request.MaskedData) {
		return nil, errors.New("DLEQ proof is invalid")
	}

	// deblinded calc
	invR := new(big.Int)
	invR.ModInverse(request.Mask, TNBCurveOrder) // mask^-1

	deblinded := &twistededwards.PointAffine{}
	deblinded.ScalarMultiplication(response.EvaluatedPoint, invR) // H *mask * sk * mask^-1 = H * sk

	x := deblinded.X.BigInt(new(big.Int))
	y := deblinded.Y.BigInt(new(big.Int))

	out := hashToScalar(x.Bytes(), y.Bytes(), request.SecretElements[0].Bytes(), request.SecretElements[1].Bytes())

	return new(big.Int).SetBytes(out), nil
}

func hashToScalar(data ...[]byte) []byte {
	hasher := hash.MIMC_BN254.New()
	for _, d := range data {
		t := d
		if len(d) == 0 {
			t = []byte{0} // otherwise hasher won't pick nil values
		}
		_, err := hasher.Write(t)
		if err != nil {
			panic(err)
		}
	}
	return hasher.Sum(nil)
}

func HashPointsToScalar(data ...*twistededwards.PointAffine) []byte {
	hasher := hash.MIMC_BN254.New()
	for _, p := range data {
		x := p.X.BigInt(new(big.Int))
		y := p.Y.BigInt(new(big.Int))
		_, err := hasher.Write(x.Bytes())
		if err != nil {
			panic(err)
		}
		_, err = hasher.Write(y.Bytes())
		if err != nil {
			panic(err)
		}
	}
	return hasher.Sum(nil)
}

func HashToCurve(data ...[]byte) *twistededwards.PointAffine {
	hashedData := hashToScalar(data...)
	scalar := new(big.Int).SetBytes(hashedData)
	params := twistededwards.GetEdwardsCurve()
	multiplicationResult := &twistededwards.PointAffine{}
	multiplicationResult.ScalarMultiplication(&params.Base, scalar)
	return multiplicationResult
}

func SetBitmask(bits []frontend.Variable, pos, length uint32) {

	p := pos * 8
	l := length * 8

	if (p + l) > uint32(len(bits)) {
		panic("invalid pos & len, out of bounds")
	}

	for i := uint32(0); i < uint32(len(bits)); i++ {
		if (i >= p) && (i < (p + l)) {
			bits[i] = 1
		} else {
			bits[i] = 0
		}
	}
}

func BEtoLE(b []byte) []byte {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-1-i] = b[len(b)-1-i], b[i]
	}
	return b
}

func OutPointToInPoint(point *twistededwards.PointAffine) tbn.Point {
	res := tbn.Point{
		X: point.X.BigInt(&big.Int{}),
		Y: point.Y.BigInt(&big.Int{}),
	}
	return res
}

func UnmarshalTBNPoint(data []byte) tbn.Point {
	e := new(twistededwards.PointAffine)
	err := e.Unmarshal(data)
	if err != nil || !e.IsOnCurve() {
		panic(err)
	}
	return OutPointToInPoint(e)
}
