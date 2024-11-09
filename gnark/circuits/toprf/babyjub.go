package toprf

import (
	"math/big"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type BabyJubParams struct {
}

func (b BabyJubParams) NbLimbs() uint     { return 4 }
func (b BabyJubParams) BitsPerLimb() uint { return 64 }
func (b BabyJubParams) IsPrime() bool     { return true }
func (b BabyJubParams) Modulus() *big.Int {
	order := tbn254.GetEdwardsCurve().Order
	return &order
}

type ScalarField = BabyJubParams
type Scalar = emulated.Element[BabyJubParams]

type BabyJubField struct {
	api frontend.API
	fr  *emulated.Field[ScalarField]
}

func NewBabyJubFieldHelper(api frontend.API) *BabyJubField {
	field, err := emulated.NewField[ScalarField](api)
	if err != nil {
		panic(err)
	}
	return &BabyJubField{
		api: api,
		fr:  field,
	}
}

func (b BabyJubField) packScalarToVar(s *Scalar) frontend.Variable {
	var fr ScalarField
	reduced := b.fr.Reduce(s)
	var res frontend.Variable = 0
	nbBits := fr.BitsPerLimb()
	coef := new(big.Int)
	one := big.NewInt(1)
	for i := range reduced.Limbs {
		res = b.api.Add(res, b.api.Mul(reduced.Limbs[i], coef.Lsh(one, nbBits*uint(i))))
	}
	return res
}
