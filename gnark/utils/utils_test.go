package utils

import (
	"encoding/base64"
	"math/big"
	"testing"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/stretchr/testify/require"
)

func TestOPRF(t *testing.T) {
	serverPrivate := "A3q7HrA+10FUiL0Q9lrDBRdRuoq752oREn9STszgLEo="
	serverPublicStr := "dGEZEZY4qexS2WyOL8KDcv99BWjL7ivaKvvarCcbYCU="
	skBytes, _ := base64.StdEncoding.DecodeString(serverPrivate)
	pubBytes, _ := base64.StdEncoding.DecodeString(serverPublicStr)

	// server secret & public
	sk := new(big.Int).SetBytes(skBytes)
	serverPublic := &tbn254.PointAffine{}
	err := serverPublic.Unmarshal(pubBytes)
	require.NoError(t, err)

	email := "test@example.com"
	ds := "reclaim"

	emailBytes := []byte(email)

	req, err := OPRFGenerateRequest(emailBytes, ds)
	require.NoError(t, err)

	resp, err := OPRFEvaluate(sk, req.MaskedData)
	require.NoError(t, err)

	res, err := OPRFFinalize(serverPublic, req, resp)
	require.NoError(t, err)

	require.Equal(t, "EnTod4kXJzeXybI7tRvGjU7GYYRXz8tEJ2Az0L2XQIc=", base64.StdEncoding.EncodeToString(res.Bytes()))

	nodes := 100
	threshold := 50
	shares, err := TOPRFCreateShares(nodes, threshold, sk)
	require.NoError(t, err)
	resps := make([]*tbn254.PointAffine, threshold)
	for i := 0; i < threshold; i++ {
		resp, err = OPRFEvaluate(shares[i].PrivateKey, req.MaskedData)
		require.NoError(t, err)
		resps[i] = resp.EvaluatedPoint
	}

	idxs := make([]int, threshold)
	for i := 0; i < threshold; i++ {
		idxs[i] = i
	}

	out, err := TOPRFFinalize(idxs, resps, req.SecretElements, req.Mask)
	require.NoError(t, err)
	require.Equal(t, "EnTod4kXJzeXybI7tRvGjU7GYYRXz8tEJ2Az0L2XQIc=", base64.StdEncoding.EncodeToString(out.Bytes()))
}
