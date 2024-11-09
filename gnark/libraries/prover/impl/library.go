package impl

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std"
)

const (
	CHACHA20      = 0
	AES_128       = 1
	AES_256       = 2
	CHACHA20_OPRF = 3
)

var algorithmNames = map[uint8]string{
	CHACHA20:      "chacha20",
	AES_128:       "aes-128-ctr",
	AES_256:       "aes-256-ctr",
	CHACHA20_OPRF: "chacha20-toprf",
}

var provers = map[string]*ProverParams{
	"chacha20": {
		KeyHash:     "967e55bd35f1333735fb62b9bda363dd307a294979c543bfc400c859b5f45fe5",
		CircuitHash: "4aa80775a6721404bf8f82fd2d78d335fabbdf517762b82a7d13e6d2446c49bf",
		Prover:      &ChaChaProver{},
	},
	"aes-128-ctr": {
		KeyHash:     "70a67f30e706a5ac91e231f23c936c3b06c4a34a7e7b578b74c70ec61473d13a",
		CircuitHash: "396128ea72136960c8a0cfddf36e2888f398116a210904745c7ed62dfcd9b115",
		Prover:      &AESProver{},
	},
	"aes-256-ctr": {
		KeyHash:     "b78c3e0b5c28c000e5338cf16e6745b8a8f2c3613d20898e88659e39c82f7de8",
		CircuitHash: "7b03be9e28a5c6de19da34cfd9fad9e7dab62cda8873fada4e916b1978bbf692",
		Prover:      &AESProver{},
	},
	"chacha20-toprf": {
		KeyHash:     "439f3aade1489f61a9f0f1cf6a70e5c98ea1ab9b41b4f45c1a6d097148bb89c4",
		CircuitHash: "dfbcff937fe1533b1f8ec36abd19213508f76f52b3923012b0024ee6d7812996",
		Prover:      &ChaChaOPRFProver{},
	},
}

type Proof struct {
	ProofJson []uint8 `json:"proofJson"`
}

type OutputParams struct {
	Proof         Proof   `json:"proof"`
	PublicSignals []uint8 `json:"publicSignals"`
}

type ProverParams struct {
	Prover
	KeyHash     string
	CircuitHash string
	initDone    bool
}

func init() {
	logger.Disable()
	std.RegisterHints()
}

func InitAlgorithm(algorithmID uint8, provingKey []byte, r1csData []byte) (res bool) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			res = false
		}
	}()
	if alg, ok := algorithmNames[algorithmID]; ok {
		proverParams := provers[alg]
		if proverParams.initDone {
			return true
		}

		inHash := sha256.Sum256(provingKey)
		keyHash := mustHex(proverParams.KeyHash)

		if subtle.ConstantTimeCompare(inHash[:], keyHash) != 1 {
			fmt.Printf("incorrect key hash %0x expected %0x \n", inHash[:], keyHash)
			return false
		}

		pkey := groth16.NewProvingKey(ecc.BN254)
		_, err := pkey.ReadFrom(bytes.NewBuffer(provingKey))
		if err != nil {
			fmt.Println(fmt.Errorf("error reading proving key: %v", err))
			return false
		}

		var r1cs constraint.ConstraintSystem
		inHash = sha256.Sum256(r1csData)
		circuitHash := mustHex(proverParams.CircuitHash)

		if subtle.ConstantTimeCompare(inHash[:], circuitHash) != 1 {
			fmt.Println(fmt.Errorf("circuit hash mismatch, expected %0x, got %0x", circuitHash, inHash[:]))
			return false
		}

		r1cs = groth16.NewCS(ecc.BN254)
		_, err = r1cs.ReadFrom(bytes.NewBuffer(r1csData))
		if err != nil {
			fmt.Println(fmt.Errorf("error reading r1cs: %v", err))
			return false
		}

		proverParams.SetParams(r1cs, pkey)
		proverParams.initDone = true
		return true
	}
	return false
}

func Prove(params []byte) []byte {
	var inputParams *InputParams
	err := json.Unmarshal(params, &inputParams)
	if err != nil {
		panic(err)
	}
	if prover, ok := provers[inputParams.Cipher]; ok {

		if !prover.initDone {
			panic(fmt.Sprintf("proving params are not initialized for cipher: %s", inputParams.Cipher))
		}
		proof, ciphertext := prover.Prove(inputParams)

		res, er := json.Marshal(&OutputParams{
			Proof: Proof{
				ProofJson: proof,
			},
			PublicSignals: ciphertext,
		})
		if er != nil {
			panic(er)
		}
		return res

	} else {
		panic("could not find prover for" + inputParams.Cipher)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
