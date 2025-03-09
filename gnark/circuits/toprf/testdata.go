package toprf

import (
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

	threshold := Threshold
	nodes := threshold + 2

	shares, err := utils.TOPRFCreateSharesDKG(nodes, threshold)
	if err != nil {
		panic(err)
	}

	idxs := utils.PickRandomIndexes(nodes, threshold)

	resps := make([]twistededwards.Point, threshold)
	respsIn := make([]*tbn254.PointAffine, threshold)
	sharePublicKeys := make([]twistededwards.Point, threshold)
	sharePublicKeysIn := make([]*tbn254.PointAffine, threshold)

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

		respsIn[i] = resp.EvaluatedPoint
		resps[i] = utils.OutPointToInPoint(resp.EvaluatedPoint)
		sharePublicKeysIn[i] = shares[idx].PublicKey
		sharePublicKeys[i] = utils.OutPointToInPoint(shares[idx].PublicKey)
		coefficients[i] = utils.Coeff(idxs[i], idxs)
		cs[i] = resp.C
		rs[i] = resp.R

	}

	// pk := utils.TOPRFThresholdMul(idxs, sharePublicKeysIn)
	// fmt.Println("master public key X:", pk.X.String())

	out, err := utils.TOPRFFinalize(idxs, respsIn, req.SecretElements, req.Mask)
	if err != nil {
		panic(err)
	}

	data := &Params{
		DomainSeparator: new(big.Int).SetBytes([]byte(domainSeparator)),
		Output:          out,
		Mask:            req.Mask,
		Counter:         req.Counter,
		X:               req.X,
	}

	copy(data.Responses[:], resps)
	copy(data.SharePublicKeys[:], sharePublicKeys)
	copy(data.Coefficients[:], coefficients)
	copy(data.C[:], cs)
	copy(data.R[:], rs)

	return data, [2]frontend.Variable{req.SecretElements[0], req.SecretElements[1]}
}
