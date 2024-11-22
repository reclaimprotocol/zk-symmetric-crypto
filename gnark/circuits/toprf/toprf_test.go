package toprf

import (
	"crypto/rand"
	"gnark-symmetric-crypto/utils"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/test"
)

func TestTOPRF(t *testing.T) {
	assert := test.NewAssert(t)
	testData, secretData := PrepareTestData("randomiiiiiiiiiiiiiizerrandomiiiiiiiiiiiiiizerrandomiiiiiiiiir", "")

	wtns := TOPRF{
		Params:     testData,
		SecretData: secretData,
	}

	assert.CheckCircuit(&wtns, test.WithCurves(ecc.BN254), test.WithValidAssignment(&wtns))
}

func TestMaskUnmask(t *testing.T) {
	assert := test.NewAssert(t)
	curve := tbn254.GetEdwardsCurve()
	data := &tbn254.PointAffine{}
	base := curve.Base
	data.ScalarMultiplication(&base, big.NewInt(12345)) // just dummy data

	// random scalar
	r, err := rand.Int(rand.Reader, utils.TNBCurveOrder)
	assert.NoError(err)

	blinded := &tbn254.PointAffine{}
	blinded.ScalarMultiplication(data, r)

	invR := &big.Int{}
	invR.ModInverse(r, utils.TNBCurveOrder)
	deblinded := &tbn254.PointAffine{}
	deblinded.ScalarMultiplication(blinded, invR)
	assert.True(deblinded.Equal(data))
}

func TestArithBN(t *testing.T) {
	assert := test.NewAssert(t)

	curveOrder := ecc.BN254.ScalarField()

	// random element
	x, _ := rand.Int(rand.Reader, curveOrder)

	// random element
	y, _ := rand.Int(rand.Reader, curveOrder)

	t1 := &bn254.G1Affine{}
	t1.ScalarMultiplicationBase(x) // G*x

	t2 := &bn254.G1Affine{}
	t2.ScalarMultiplicationBase(y) // G*y

	t3 := &bn254.G1Affine{}
	t3.Add(t1, t2) // G*x + G*y

	z := new(big.Int)
	z.Add(x, y)
	z.Mod(z, curveOrder)

	t4 := &bn254.G1Affine{}
	t4.ScalarMultiplicationBase(z)
	assert.True(t4.Equal(t3))

	w := new(big.Int)
	w.Neg(y)
	w.Mod(w, curveOrder)
	t5 := &bn254.G1Affine{}
	t5.ScalarMultiplicationBase(w) // G* -y

	t6 := &bn254.G1Affine{}
	t6.Add(t3, t5) // G* -y + G*x + G*y = G*x

	assert.True(t6.Equal(t1))
}

func TestArithBabyJub(t *testing.T) {
	assert := test.NewAssert(t)

	curveOrder := tbn254.GetEdwardsCurve().Order
	base := tbn254.GetEdwardsCurve().Base

	// random element
	x, _ := rand.Int(rand.Reader, &curveOrder)

	// random element
	y, _ := rand.Int(rand.Reader, &curveOrder)

	t1 := &tbn254.PointAffine{}
	t1.ScalarMultiplication(&base, x) // G*x

	t2 := &tbn254.PointAffine{}
	t2.ScalarMultiplication(&base, y) // G*y

	t3 := &tbn254.PointAffine{}
	t3.Add(t1, t2) // G*x + G*y

	z := new(big.Int)
	z.Add(x, y) // x+y
	z.Mod(z, &curveOrder)

	t4 := &tbn254.PointAffine{}
	t4.ScalarMultiplication(&base, z) // G * (x+y)
	assert.True(t4.Equal(t3))

	w := new(big.Int)
	w.Neg(y) // -y
	w.Mod(w, &curveOrder)
	t5 := &tbn254.PointAffine{}
	t5.ScalarMultiplication(&base, w) // G* -y

	t6 := &tbn254.PointAffine{}
	t6.Add(t3, t5) // G* -y + G*x + G*y = G*x

	assert.True(t6.Equal(t1))
}
