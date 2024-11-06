package oprf

import (
	"encoding/json"
	"gnark-symmetric-crypto/utils"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

type InputOPRFParams struct {
	ServerPrivate []byte `json:"serverPrivate"`
	MaskedData    []byte `json:"maskedData"`
}

type OutputOPRFParams struct {
	Response []byte `json:"response"`
	C        []byte `json:"c"`
	S        []byte `json:"s"`
}

func OPRFEvaluate(params []byte) []byte {
	var inputParams *InputOPRFParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		panic(err)
	}

	maskedData := new(twistededwards.PointAffine)
	err = maskedData.Unmarshal(inputParams.MaskedData)
	if err != nil {
		panic(err)
	}
	resp, err := utils.OPRFEvaluate(new(big.Int).SetBytes(inputParams.ServerPrivate), maskedData)
	if err != nil {
		panic(err)
	}

	res, err := json.Marshal(&OutputOPRFParams{
		Response: resp.EvaluatedPoint.Marshal(),
		C:        resp.C.Bytes(),
		S:        resp.R.Bytes(),
	})
	if err != nil {
		panic(err)
	}
	return res
}

type InputGenerateParams struct {
	Nodes     uint8 `json:"nodes"`
	Threshold uint8 `json:"threshold"`
}

type Share struct {
	Index      int
	PrivateKey []byte `json:"privateKey"`
	PublicKey  []byte `json:"publicKey"`
}

type OutputGenerateParams struct {
	PrivateKey []byte   `json:"privateKey"`
	PublicKey  []byte   `json:"publicKey"`
	Shares     []*Share `json:"shares"`
}

func TOPRFGenerateSharedKey(params []byte) []byte {

	var inputParams *InputGenerateParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		panic(err)
	}

	threshold := inputParams.Threshold
	nodes := inputParams.Nodes

	if threshold >= nodes {
		panic("threshold must be smaller than nodes")
	}

	keyParams := utils.TOPRFGenerateSharedKey(int(nodes), int(threshold))
	shareParams := make([]*Share, nodes)
	for i, share := range keyParams.Shares {
		shareParams[i] = &Share{
			Index:      i,
			PrivateKey: share.PrivateKey.Bytes(),
			PublicKey:  share.PublicKey.Marshal(),
		}
	}
	res := &OutputGenerateParams{
		PrivateKey: keyParams.PrivateKey.Bytes(),
		PublicKey:  keyParams.PublicKey.Marshal(),
		Shares:     shareParams,
	}

	bRes, err := json.Marshal(&res)
	if err != nil {
		panic(err)
	}

	return bRes
}
