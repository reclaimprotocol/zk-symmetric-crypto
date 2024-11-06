package oprf

import (
	"encoding/json"
	"gnark-symmetric-crypto/utils"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type InputGenerateParams struct {
	Data            string `json:"data"`
	DomainSeparator string `json:"domainSeparator"`
}
type OutputGenerateParams struct {
	Mask       []byte `json:"mask"`
	MaskedData []byte `json:"maskedData"`
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

	res, err := json.Marshal(&OutputGenerateParams{
		Mask:       req.Mask.Bytes(),
		MaskedData: req.MaskedData.Marshal(),
	})
	if err != nil {
		panic(err)
	}
	return res
}

type OPRFRequest struct {
	Mask       []byte `json:"mask"`
	MaskedData []byte `json:"maskedData"`
}

type OPRFResponse struct {
	Response []byte `json:"response"`
	C        []byte `json:"c"`
	S        []byte `json:"s"`
}

type InputOPRFResponseParams struct {
	ServerPublicKey []byte        `json:"serverPublicKey"`
	Request         *OPRFRequest  `json:"request"`
	Response        *OPRFResponse `json:"response"`
}

type OutputOPRFResponseParams struct {
	Output []byte `json:"output"`
}

func ProcessOPRFResponse(params []byte) []byte {
	var inputParams *InputOPRFResponseParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		panic(err)
	}

	serverPublicKey := new(twistededwards.PointAffine)
	err = serverPublicKey.Unmarshal(inputParams.ServerPublicKey)
	if err != nil {
		panic(err)
	}
	maskedData := new(twistededwards.PointAffine)
	err = maskedData.Unmarshal(inputParams.Request.MaskedData)
	if err != nil {
		panic(err)
	}
	req := &utils.OPRFRequest{
		Mask:       new(big.Int).SetBytes(inputParams.Request.Mask),
		MaskedData: maskedData,
	}

	oprfResponse := new(twistededwards.PointAffine)
	err = oprfResponse.Unmarshal(inputParams.Response.Response)
	if err != nil {
		panic(err)
	}
	resp := &utils.OPRFResponse{
		EvaluatedPoint: oprfResponse,
		C:              new(big.Int).SetBytes(inputParams.Response.C),
		R:              new(big.Int).SetBytes(inputParams.Response.S),
	}

	output, err := utils.OPRFFinalize(serverPublicKey, req, resp)
	if err != nil {
		panic(err)
	}

	res, err := json.Marshal(&OutputOPRFResponseParams{
		Output: output.Bytes(),
	})
	if err != nil {
		panic(err)
	}
	return res
}
