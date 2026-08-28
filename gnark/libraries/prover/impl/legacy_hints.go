package impl

import (
	"errors"
	"hash/fnv"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	babyjubjub "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
)

const (
	legacyHalfGCDHintName   = "github.com/consensys/gnark/std/algebra/native/twistededwards.halfGCD"
	legacyScalarMulHintName = "github.com/consensys/gnark/std/algebra/native/twistededwards.scalarMulHint"
)

func init() {
	solver.RegisterNamedHint(legacyHalfGCD, legacyHintID(legacyHalfGCDHintName))
}

func legacyHintID(name string) solver.HintID {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(name))
	return solver.HintID(hash.Sum32())
}

func legacyProverOptions() []backend.ProverOption {
	return []backend.ProverOption{
		backend.WithSolverOptions(
			solver.OverrideHint(legacyHintID(legacyScalarMulHintName), legacyScalarMulHint),
		),
	}
}

// legacyHalfGCD preserves the hint contract embedded in the immutable gnark
// v0.14 constraint systems. Gnark v0.16 replaced this hint with a different
// decomposition, but existing proving keys and constraint systems still refer
// to the original name and four-output contract.
func legacyHalfGCD(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	if inputs[0].Sign() == 0 {
		for i := range outputs {
			outputs[i].SetUint64(0)
		}
		return nil
	}

	lattice := new(ecc.Lattice)
	ecc.PrecomputeLattice(inputs[1], inputs[0], lattice)
	outputs[0].Set(&lattice.V1[0])
	outputs[1].Set(&lattice.V1[1])

	// s2*s + s1 = k*r.
	outputs[3].Mul(outputs[1], inputs[0]).
		Add(outputs[3], outputs[0]).
		Div(outputs[3], inputs[1])

	outputs[2].SetUint64(0)
	if outputs[1].Sign() == -1 {
		outputs[1].Neg(outputs[1])
		outputs[2].SetUint64(1)
	}

	return nil
}

// legacyScalarMulHint preserves the four-input/two-output BN254 hint contract
// embedded in the immutable gnark v0.14 constraint systems.
func legacyScalarMulHint(field *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return errors.New("expecting four inputs")
	}
	if len(outputs) != 2 {
		return errors.New("expecting two outputs")
	}
	if field.Cmp(ecc.BN254.ScalarField()) != 0 {
		return errors.New("legacy scalarMulHint: unsupported curve")
	}

	var point babyjubjub.PointAffine
	point.X.SetBigInt(inputs[0])
	point.Y.SetBigInt(inputs[1])
	point.ScalarMultiplication(&point, inputs[2])
	point.X.BigInt(outputs[0])
	point.Y.BigInt(outputs[1])
	return nil
}
