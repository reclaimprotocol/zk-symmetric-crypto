package utils

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

func ProveDLEQ(x *big.Int, H *twistededwards.PointAffine) (*big.Int, *big.Int, error) {
	curve := twistededwards.GetEdwardsCurve()
	base := curve.Base

	// xG = G*x, xH = H*x
	xG := new(twistededwards.PointAffine).ScalarMultiplication(&base, x)
	xH := new(twistededwards.PointAffine).ScalarMultiplication(H, x)

	// random scalar
	v, err := rand.Int(rand.Reader, TNBCurveOrder)
	if err != nil {
		return nil, nil, err
	}

	vG := new(twistededwards.PointAffine).ScalarMultiplication(&base, v)
	vH := new(twistededwards.PointAffine).ScalarMultiplication(H, v)

	challengeHash := HashPointsToScalar(&base, xG, vG, vH, H, xH)
	c := new(big.Int).SetBytes(challengeHash)

	r := new(big.Int).Neg(c)
	r.Mul(r, x)
	r.Add(r, v)
	r.Mod(r, TNBCurveOrder)

	return c, r, nil
}

func VerifyDLEQ(c, r *big.Int, xG, xH, H *twistededwards.PointAffine) bool {
	curve := twistededwards.GetEdwardsCurve()
	base := curve.Base

	// vG = r*G + c*xG
	rg := new(twistededwards.PointAffine).ScalarMultiplication(&base, r)
	chg := new(twistededwards.PointAffine).ScalarMultiplication(xG, c)
	vG := rg.Add(rg, chg)

	// vH = r*H + c*xH
	rH := new(twistededwards.PointAffine).ScalarMultiplication(H, r)
	cH := new(twistededwards.PointAffine).ScalarMultiplication(xH, c)
	vH := cH.Add(rH, cH)

	verifyHash := HashPointsToScalar(&base, xG, vG, vH, H, xH)
	verifyNum := new(big.Int).SetBytes(verifyHash)
	return verifyNum.Cmp(c) == 0
}
