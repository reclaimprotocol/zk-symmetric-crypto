package utils

import (
	"crypto/rand"
	"errors"
	"fmt"

	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	tbn "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

var TNBCurveOrder = func() *big.Int { order := twistededwards.GetEdwardsCurve().Order; return &order }()

const BytesPerElement = 31

type OPRFRequest struct {
	Mask           *big.Int `json:"mask"`
	MaskedData     *twistededwards.PointAffine
	SecretElements [2]*big.Int
	Counter        int
	X              fr.Element // original X
	Y              fr.Element // cleared Y
}

type OPRFResponse struct {
	EvaluatedPoint *twistededwards.PointAffine
	C              *big.Int
	R              *big.Int
}

func OPRFGenerateRequest(secretBytes []byte, domainSeparator string) (*OPRFRequest, error) {
	if len(secretBytes) > BytesPerElement*2 {
		return nil, fmt.Errorf("secret data too big: %d, max %d bytes is allowed", len(secretBytes), BytesPerElement*2)
	}
	domainBytes := []byte(domainSeparator)
	if len(domainBytes) > BytesPerElement {
		return nil, fmt.Errorf("domain separator is %d bytes, max %d bytes is allowed", len(domainBytes), BytesPerElement)
	}

	var secretElements [2]*big.Int

	if len(secretBytes) > BytesPerElement {
		secretElements[0] = new(big.Int).SetBytes(BEtoLE(secretBytes[:BytesPerElement]))
		secretElements[1] = new(big.Int).SetBytes(BEtoLE(secretBytes[BytesPerElement:]))
	} else {
		secretElements[0] = new(big.Int).SetBytes(BEtoLE(secretBytes))
		secretElements[1] = big.NewInt(0)
	}

	H, origX, counter, err := HashToPointPrecompute(secretElements[0].Bytes(), secretElements[1].Bytes(), domainBytes) // H
	if err != nil {
		return nil, err
	}
	if !H.IsOnCurve() {
		return nil, errors.New("point is not on curve")
	}

	// random mask
	mask, err := rand.Int(rand.Reader, TNBCurveOrder)
	if err != nil {
		return nil, err
	}
	masked := &twistededwards.PointAffine{}
	masked.ScalarMultiplication(H, mask) // H*mask

	x := new(big.Int)
	H.X.BigInt(x)
	return &OPRFRequest{
		Mask:           mask,
		MaskedData:     masked,
		SecretElements: secretElements,
		Counter:        counter,
		X:              *origX,
		Y:              H.Y,
	}, nil
}

func OPRFEvaluate(serverPrivate *big.Int, request *twistededwards.PointAffine) (*OPRFResponse, error) {
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
		y := p.Y.BigInt(new(big.Int))
		_, err := hasher.Write(y.Bytes())
		if err != nil {
			panic(err)
		}
	}
	return hasher.Sum(nil)
}

func HashToPointPrecompute(data ...[]byte) (*twistededwards.PointAffine, *fr.Element, int, error) {
	var a, d, one fr.Element
	a.SetInt64(-1)
	d = curve.D
	one.SetOne()

	for counter := 0; counter <= 255; counter++ {
		var counterFr fr.Element
		counterFr.SetInt64(int64(counter))
		yBytes := hashToScalar(append(data, counterFr.Marshal())...)
		var y fr.Element
		y.SetBytes(yBytes)

		var y2, num, denom, x2 fr.Element
		y2.Square(&y)
		num.Sub(&one, &y2)
		denom.Mul(&d, &y2).Add(&denom, &one).Neg(&denom)
		if denom.IsZero() {
			// fmt.Printf("Counter %d: x² denominator is zero\n", counter)
			continue
		}
		x2.Div(&num, &denom)

		// fmt.Printf("Counter %d: y² = %s, x² = %s, Legendre(x²) = %d\n", counter, y2.String(), x2.String(), x2.Legendre())
		var x fr.Element
		if x.Sqrt(&x2) != nil {
			point := twistededwards.PointAffine{X: x, Y: y}
			if point.IsOnCurve() {
				clearedPoint := point.ScalarMultiplication(&point, big.NewInt(8))
				if !clearedPoint.IsOnCurve() {
					return nil, nil, 0, fmt.Errorf("cofactor-cleared point not on curve")
				}
				return clearedPoint, &x, counter, nil
			}
			var lhs, rhs fr.Element
			lhs.Mul(&a, &x2).Add(&lhs, &y2)
			rhs.Mul(&d, &x2).Mul(&rhs, &y2).Add(&rhs, &one)
			// fmt.Printf("Counter %d: LHS = %s\nRHS = %s\n", counter, lhs.String(), rhs.String())
			// fmt.Printf("Counter %d: Point not on curve: x=%s, y=%s\n", counter, x.String(), y.String())
		}
	}

	return nil, nil, 0, fmt.Errorf("failed to find valid point after 256 attempts")
}

func SetBitmask(bits []frontend.Variable, pos, length uint32) {

	p := pos * 8
	l := length * 8

	if (p + l) > uint32(len(bits)) {
		panic(fmt.Sprintf("invalid pos and length, out of bounds. pos %d, length %d", p, l))
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
	res := make([]byte, len(b))
	copy(res, b)
	for i := 0; i < len(res)/2; i++ {
		res[i], res[len(res)-1-i] = b[len(res)-1-i], res[i]
	}
	return res
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
