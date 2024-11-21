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
		KeyHash:     "bf4901012e00a7517a6da2e4c4d3922d90051609726c8488b2a6045b030e44eb",
		CircuitHash: "4aa80775a6721404bf8f82fd2d78d335fabbdf517762b82a7d13e6d2446c49bf",
		Prover:      &ChaChaProver{},
	},
	"aes-128-ctr": {
		KeyHash:     "a3c41ab381f31a0820817a8d2e928f276487da3bf3e61285791689388af27017",
		CircuitHash: "b1ee478f009fe81946e6e2768ef0b6d62ab266525f186baaa4e8dec61b6e3ea6",
		Prover:      &AESProver{},
	},
	"aes-256-ctr": {
		KeyHash:     "94a9df9edad28462f1d523b191c9caf3aa07751ca5f5e4cf458614f1fc72c198",
		CircuitHash: "e62f8e74b17cad4012513cf23971ddf58faa63a4a87676047bccd255021dee13",
		Prover:      &AESProver{},
	},
	"chacha20-toprf": {
		KeyHash:     "14ee5e7b36ce6b47ee4e344deafd7573a8dc9554f899f410328764a84c77f719",
		CircuitHash: "b5fbd1900eabb8e3a12cf0896cfd7f5b2b6290d536e0f6bd7b9eb09caf9c0f7e",
		Prover:      &ChaChaOPRFProver{},
	},
	"aes-128-ctr-toprf": {
		KeyHash:     "a8171697bc39e84446f27652ccd6d2dfca1829e93833780068a8e0e16e44410a",
		CircuitHash: "38dfce7e54a8872035c5b67e70cf74aaf6b2cc37a5ea2b7f86bea1191e7647b0",
		Prover:      &AESOPRFProver{},
	},
	"aes-256-ctr-toprf": {
		KeyHash:     "e9259ca30016f85e4c9377aee4524ebaf8af8d54e045a1d4753b04ceada68c08",
		CircuitHash: "182e1cfabfdddbf91bf475544f173e74b48d40debef1e85bcf02068ffee08c97",
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
