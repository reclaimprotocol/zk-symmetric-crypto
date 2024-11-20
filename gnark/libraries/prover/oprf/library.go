package oprf

import (
	"encoding/json"
	"fmt"
	"gnark-symmetric-crypto/circuits/toprf"
	"gnark-symmetric-crypto/utils"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type InputGenerateParams struct {
	Data            []byte `json:"data"`
	DomainSeparator string `json:"domainSeparator"`
}
type OPRFRequest struct {
	Mask           []byte   `json:"mask"`
	MaskedData     []byte   `json:"maskedData"`
	SecretElements [][]byte `json:"secretElements"`
}

func GenerateOPRFRequestData(params []byte) []byte {
	var inputParams *InputGenerateParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		panic(err)
	}

	req, err := utils.OPRFGenerateRequest(inputParams.Data, inputParams.DomainSeparator)
	if err != nil {
		panic(err)
	}

	res, err := json.Marshal(&OPRFRequest{
		Mask:           req.Mask.Bytes(),
		MaskedData:     req.MaskedData.Marshal(),
		SecretElements: [][]byte{req.SecretElements[0].Bytes(), req.SecretElements[1].Bytes()},
	})
	if err != nil {
		panic(err)
	}
	return res
}

type OPRFResponse struct {
	Index          uint8  `json:"index"`
	PublicKeyShare []byte `json:"publicKeyShare"`
	Evaluated      []byte `json:"evaluated"`
	C              []byte `json:"c"`
	R              []byte `json:"r"`
}

type InputTOPRFFinalizeParams struct {
	ServerPublicKey []byte          `json:"serverPublicKey"`
	Request         *OPRFRequest    `json:"request"`
	Responses       []*OPRFResponse `json:"responses"`
}

type OutputOPRFResponseParams struct {
	Output []byte `json:"output"`
}

func TOPRFFinalize(params []byte) []byte {
	var inputParams *InputTOPRFFinalizeParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		panic(err)
	}

	serverPublicKey := new(twistededwards.PointAffine)
	err = serverPublicKey.Unmarshal(inputParams.ServerPublicKey)
	if err != nil {
		panic(err)
	}
	if !serverPublicKey.IsOnCurve() {
		panic("server public key is not on curve")
	}
	maskedData := new(twistededwards.PointAffine)
	err = maskedData.Unmarshal(inputParams.Request.MaskedData)
	if err != nil {
		panic(err)
	}
	if !maskedData.IsOnCurve() {
		panic("masked data is not on curve")
	}

	if len(inputParams.Responses) != toprf.Threshold {
		panic(fmt.Sprintf("Must provide exactly %d responses", toprf.Threshold))
	}

	elements := make([]*twistededwards.PointAffine, toprf.Threshold)
	idxs := make([]int, toprf.Threshold)
	for i := 0; i < toprf.Threshold; i++ {
		elements[i] = &twistededwards.PointAffine{}
		err = elements[i].Unmarshal(inputParams.Responses[i].Evaluated)
		if err != nil {
			panic(err)
		}
		if !elements[i].IsOnCurve() {
			panic("evaluated element is not on curve")
		}
		idxs[i] = int(inputParams.Responses[i].Index)
	}

	mask := new(big.Int).SetBytes(inputParams.Request.Mask)

	if len(inputParams.Request.SecretElements) != 2 {
		panic("wrong number of secret elements")
	}

	var secretElements [2]*big.Int
	secretElements[0] = new(big.Int).SetBytes(inputParams.Request.SecretElements[0])
	secretElements[1] = new(big.Int).SetBytes(inputParams.Request.SecretElements[1])

	out, err := utils.TOPRFFinalize(idxs, elements, secretElements, mask)
	if err != nil {
		panic(err)
	}

	res, err := json.Marshal(&OutputOPRFResponseParams{
		Output: out.Bytes(),
	})
	if err != nil {
		panic(err)
	}
	return res
}
