package toprf

import (
	"crypto/rand"
	"gnark-symmetric-crypto/utils"
	"math/big"

	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type Proof struct {
	ServerPublicKey twistededwards.Point
	Challenge       *big.Int
	Proof           *big.Int
}

type TestData struct {
	Response   twistededwards.Point
	SecretData *big.Int
	Output     twistededwards.Point
	Mask       *big.Int
	InvMask    *big.Int
	Proof      *Proof
}

func PrepareTestData(secretData string, domainSeparator string) (*Params, [2]frontend.Variable) {
	req, err := utils.OPRFGenerateRequest([]byte(secretData), domainSeparator)
	if err != nil {
		panic(err)
	}

	// server secret
	curve := tbn254.GetEdwardsCurve()
	sk, _ := rand.Int(rand.Reader, utils.TNBCurveOrder)
	serverPublic := &tbn254.PointAffine{}
	serverPublic.ScalarMultiplication(&curve.Base, sk) // G*sk

	threshold := Threshold
	nodes := threshold + 2

	shares, err := utils.TOPRFCreateShares(nodes, threshold, sk)
	if err != nil {
		panic(err)
	}

	idxs := utils.PickRandomIndexes(nodes, threshold)

	resps := make([]twistededwards.Point, threshold)
	sharePublicKeys := make([]twistededwards.Point, threshold)
	coefficients := make([]frontend.Variable, threshold)
	cs := make([]frontend.Variable, threshold)
	rs := make([]frontend.Variable, threshold)

	for i := 0; i < threshold; i++ {

		idx := idxs[i]

		var resp *utils.OPRFResponse
		resp, err = utils.OPRFEvaluate(shares[idx].PrivateKey, req.MaskedData)
		if err != nil {
			panic(err)
		}

		resps[i] = utils.OutPointToInPoint(resp.EvaluatedPoint)
		sharePublicKeys[i] = utils.OutPointToInPoint(shares[idx].PublicKey)
		coefficients[i] = utils.Coeff(idxs[i], idxs)
		cs[i] = resp.C
		rs[i] = resp.R

	}

	// without TOPRF
	resp, err := utils.OPRFEvaluate(sk, req.MaskedData)
	if err != nil {
		panic(err)
	}

	out, err := utils.OPRFFinalize(serverPublic, req, resp)
	if err != nil {
		panic(err)
	}

	data := &Params{
		DomainSeparator: new(big.Int).SetBytes([]byte(domainSeparator)),
		Output:          out,
		Mask:            req.Mask,
	}

	copy(data.Responses[:], resps)
	copy(data.SharePublicKeys[:], sharePublicKeys)
	copy(data.Coefficients[:], coefficients)
	copy(data.C[:], cs)
	copy(data.R[:], rs)

	return data, [2]frontend.Variable{req.SecretElements[0], req.SecretElements[1]}
}
