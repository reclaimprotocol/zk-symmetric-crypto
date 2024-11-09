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
	xG := new(twistededwards.PointAffine)
	xG.ScalarMultiplication(&base, x)

	xH := new(twistededwards.PointAffine)
	xH.ScalarMultiplication(H, x)

	// random scalar
	v, err := rand.Int(rand.Reader, TNBCurveOrder)
	if err != nil {
		return nil, nil, err
	}

	vG := new(twistededwards.PointAffine)
	vG.ScalarMultiplication(&base, v) // G*v

	vH := new(twistededwards.PointAffine)
	vH.ScalarMultiplication(H, v) // H*v

	challengeHash := HashPointsToScalar(&base, xG, vG, vH, H, xH)
	c := new(big.Int).SetBytes(challengeHash)
	// c.Mod(c, scalarField) // ?

	r := new(big.Int).Neg(c) // -c
	r.Mul(r, x)              // -c*x
	r.Add(r, v)              // v - c*x
	r.Mod(r, TNBCurveOrder)

	return c, r, nil
}

func VerifyDLEQ(c, r *big.Int, xG, xH, H *twistededwards.PointAffine) bool {
	curve := twistededwards.GetEdwardsCurve()
	base := curve.Base

	/*
		vG==rG+c(xG)
		vH==rH+c(xH)
	*/
	rg := new(twistededwards.PointAffine).ScalarMultiplication(&base, r) // G * Mask = G * (v-c*x)
	chg := new(twistededwards.PointAffine).ScalarMultiplication(xG, c)   // G*x*c

	vG := rg.Add(rg, chg) // G * (v-c*x) + G*x*c =G*v − G*c*x + G*c*x = vG

	rH := new(twistededwards.PointAffine).ScalarMultiplication(H, r)  // H * Mask = H * (v-c*x)
	cH := new(twistededwards.PointAffine).ScalarMultiplication(xH, c) // H*x*c

	vH := cH.Add(rH, cH) // H * (v-c*x) + H*x*c =H*v − H*c*x + H*c*x = vH

	verifyHash := HashPointsToScalar(&base, xG, vG, vH, H, xH)
	verifyNum := new(big.Int).SetBytes(verifyHash)
	return verifyNum.Cmp(c) == 0
}
