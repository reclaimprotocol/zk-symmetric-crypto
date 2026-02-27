package utils

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

var cofactor = big.NewInt(8)

// clearCofactor multiplies point by cofactor to ensure it's in prime-order subgroup.
// Returns nil if the result is identity (point was in small subgroup).
func clearCofactor(p *twistededwards.PointAffine) *twistededwards.PointAffine {
	cleared := new(twistededwards.PointAffine).ScalarMultiplication(p, cofactor)
	if cleared.X.IsZero() {
		return nil
	}
	return cleared
}

func ProveDLEQ(x *big.Int, H *twistededwards.PointAffine) (*big.Int, *big.Int, error) {
	curve := twistededwards.GetEdwardsCurve()
	base := curve.Base

	// xG = G*x, xH = H*x
	xG := new(twistededwards.PointAffine).ScalarMultiplication(&base, x)
	xH := new(twistededwards.PointAffine).ScalarMultiplication(H, x)

	// Clear cofactor per RFC 9497 - ensures points are in prime-order subgroup
	xGCleared := clearCofactor(xG)
	xHCleared := clearCofactor(xH)

	// Effective secret for cleared points: 8*x mod r
	effectiveX := new(big.Int).Mul(x, cofactor)
	effectiveX.Mod(effectiveX, TNBCurveOrder)

	// random scalar
	v, err := rand.Int(rand.Reader, TNBCurveOrder)
	if err != nil {
		return nil, nil, err
	}

	vG := new(twistededwards.PointAffine).ScalarMultiplication(&base, v)
	vH := new(twistededwards.PointAffine).ScalarMultiplication(H, v)

	challengeHash := HashPointsToScalar(&base, xGCleared, vG, vH, H, xHCleared)
	c := new(big.Int).SetBytes(challengeHash)

	r := new(big.Int).Neg(c)
	r.Mul(r, effectiveX)
	r.Add(r, v)
	r.Mod(r, TNBCurveOrder)

	return c, r, nil
}

func VerifyDLEQ(c, r *big.Int, xG, xH, H *twistededwards.PointAffine) bool {
	curve := twistededwards.GetEdwardsCurve()
	base := curve.Base

	// Clear cofactor per RFC 9497 - ensures points are in prime-order subgroup
	xGCleared := clearCofactor(xG)
	xHCleared := clearCofactor(xH)
	if xGCleared == nil || xHCleared == nil {
		return false
	}

	// vG = r*G + c*xGCleared
	rg := new(twistededwards.PointAffine).ScalarMultiplication(&base, r)
	chg := new(twistededwards.PointAffine).ScalarMultiplication(xGCleared, c)
	vG := rg.Add(rg, chg)

	// vH = r*H + c*xHCleared
	rH := new(twistededwards.PointAffine).ScalarMultiplication(H, r)
	cH := new(twistededwards.PointAffine).ScalarMultiplication(xHCleared, c)
	vH := cH.Add(rH, cH)

	verifyHash := HashPointsToScalar(&base, xGCleared, vG, vH, H, xHCleared)
	verifyNum := new(big.Int).SetBytes(verifyHash)
	return verifyNum.Cmp(c) == 0
}
