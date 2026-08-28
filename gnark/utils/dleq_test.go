package utils

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/stretchr/testify/require"
)

func TestVerifyDLEQAcceptsLegacyAttestorTranscript(t *testing.T) {
	publicKey := decodePoint(t, "88b290b557ad4258f65534f3a91612144fd815d488fcce5c67d20a194ebedf8f")
	evaluated := decodePoint(t, "88b83c0ffb8c779714250ff02b275ca3a0d549e24c916c05a2b969e27b6ac8a0")
	maskedData := decodePoint(t, "267942d0e5cdad9ee90cf68678921753fb2d7cf65d1bc1be02ab8d3c23e46b8f")
	c := decodeScalar(t, "02a18160fd99e23ad5e504f855acf9c9817b6cbd5d009d339922e3998825d803")
	r := decodeScalar(t, "0562eda79640f3c213905829f7fda671422ade51883d9b0c6e18096fc006923f")

	require.True(t, VerifyDLEQ(c, r, publicKey, evaluated, maskedData))

	tamperedR := new(big.Int).Add(r, big.NewInt(1))
	tamperedR.Mod(tamperedR, TNBCurveOrder)
	require.False(t, VerifyDLEQ(c, tamperedR, publicKey, evaluated, maskedData))
}

func TestOPRFEvaluateRejectsSmallSubgroup(t *testing.T) {
	identity := new(twistededwards.PointAffine)
	identity.X.SetZero()
	identity.Y.SetOne()

	_, err := OPRFEvaluate(big.NewInt(1), identity)
	require.EqualError(t, err, "request point is in small subgroup")
}

func decodePoint(t *testing.T, value string) *twistededwards.PointAffine {
	t.Helper()

	encoded, err := hex.DecodeString(value)
	require.NoError(t, err)

	point := new(twistededwards.PointAffine)
	require.NoError(t, point.Unmarshal(encoded))
	return point
}

func decodeScalar(t *testing.T, value string) *big.Int {
	t.Helper()

	encoded, err := hex.DecodeString(value)
	require.NoError(t, err)
	return new(big.Int).SetBytes(encoded)
}
