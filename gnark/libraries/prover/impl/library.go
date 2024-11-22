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
	AES_128_OPRF  = 4
	AES_256_OPRF  = 5
)

var algorithmNames = map[uint8]string{
	CHACHA20:      "chacha20",
	AES_128:       "aes-128-ctr",
	AES_256:       "aes-256-ctr",
	CHACHA20_OPRF: "chacha20-toprf",
	AES_128_OPRF:  "aes-128-ctr-toprf",
	AES_256_OPRF:  "aes-256-ctr-toprf",
}

var provers = map[string]*ProverParams{
	"chacha20": {
		KeyHash:     "4bfc68e4cf1fc95a8bcd83b07ca980c227c3a333c1c70d1ef5ab7982ea2cc30b",
		CircuitHash: "4382aa593cfe8f3b3dcd35cff62a27d8ca2b415dae64bdeca2a561a707fabab0",
		Prover:      &ChaChaProver{},
	},
	"aes-128-ctr": {
		KeyHash:     "618fe3b1781170993eb8645925335ece4bd22277c26b372bf9713dcbeecf84f1",
		CircuitHash: "b1ee478f009fe81946e6e2768ef0b6d62ab266525f186baaa4e8dec61b6e3ea6",
		Prover:      &AESProver{},
	},
	"aes-256-ctr": {
		KeyHash:     "522e51d29d81605e0211485ee5630a52b85cb0f88e476e85b74ab4db7b482c27",
		CircuitHash: "e62f8e74b17cad4012513cf23971ddf58faa63a4a87676047bccd255021dee13",
		Prover:      &AESProver{},
	},
	"chacha20-toprf": {
		KeyHash:     "153dd306e5f90d1c239cc63efa1a98e19e5d6fac6fb22dc1b18c4bffd23be5c2",
		CircuitHash: "9107e9b1fbb174cff7a662e02c8f3f04dd6c8ba305303a94f5d0513dda5b0fd9",
		Prover:      &ChaChaOPRFProver{},
	},
	"aes-128-ctr-toprf": {
		KeyHash:     "aae5e5e48cb75802aef73f8b0e0384d665c4f26e04227352f10a3401767b1986",
		CircuitHash: "33b0c9bbc6c2a3e322027f48ecc8d20590e44ed772db1a896990c043325ef3e0",
		Prover:      &AESOPRFProver{},
	},
	"aes-256-ctr-toprf": {
		KeyHash:     "a3c5c6ef394ac3edb158de12b235bce836bd9c3a0286787c92648bbce8830adb",
		CircuitHash: "58ba58ff0124a662f6643f5ba081fb88a4f7f5bdadaeddc003fc2cc3e26d8ec2",
		Prover:      &AESOPRFProver{},
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
