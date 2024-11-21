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
		KeyHash:     "78ab307e3d5065d21b2c068824286054846724e5f1f868cd22ed273902b9c440",
		CircuitHash: "4aa80775a6721404bf8f82fd2d78d335fabbdf517762b82a7d13e6d2446c49bf",
		Prover:      &ChaChaProver{},
	},
	"aes-128-ctr": {
		KeyHash:     "7f89cf1ef3476069ed1c107abbe02080d5eecd50ebd0ff3a858d9f557cf0ae7d",
		CircuitHash: "e59bd07d4450f98663b62a2ef06b2d7de4044601c755c74da7dde3cb0a6e8893",
		Prover:      &AESProver{},
	},
	"aes-256-ctr": {
		KeyHash:     "233d52d78ef5ff9f9e8d97d238524acdbaf007121d56bcd7b26b72df74488fc0",
		CircuitHash: "32c0eeb1c59c45b05eeefa00f637a4d02b208990ae1ff33b62d85c8bcef73b2d",
		Prover:      &AESProver{},
	},
	"chacha20-toprf": {
		KeyHash:     "75386aa3fd0cb51a74d02df3e1a66b60edb11a8925a89a5bfd8d3333106f6ce0",
		CircuitHash: "b5fbd1900eabb8e3a12cf0896cfd7f5b2b6290d536e0f6bd7b9eb09caf9c0f7e",
		Prover:      &ChaChaOPRFProver{},
	},
	"aes-128-ctr-toprf": {
		KeyHash:     "c74414b5417a01d795a28d4cb78bc64f2597690a09bd35c333198636a558eab6",
		CircuitHash: "38dfce7e54a8872035c5b67e70cf74aaf6b2cc37a5ea2b7f86bea1191e7647b0",
		Prover:      &AESOPRFProver{},
	},
	"aes-256-ctr-toprf": {
		KeyHash:     "d8a32865925a2bbe85976a1ab44fb7bd78ded2998c277f051ce0859086e440dd",
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
