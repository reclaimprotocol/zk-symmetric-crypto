package impl

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/rs/zerolog"
)

const (
	CHACHA20 = 0
	AES_128  = 1
	AES_256  = 2
)

var algorithmNames = map[uint8]string{
	CHACHA20: "chacha20",
	AES_128:  "aes-128-ctr",
	AES_256:  "aes-256-ctr",
}

var provers = map[string]*ProverParams{
	"chacha20": {
		KeyHash:     "e609f370a46ba5e7cbe192fc5c44e402eea00e76d235568c0079d7f1e36727e4",
		CircuitHash: "64193c545bfc4ea3e52af66beb05a02551337520ddd2a25e08b0b224730afae3",
		Prover:      &ChaChaProver{},
	},
	"aes-128-ctr": {
		KeyHash:     "632015cc2db4fbdb89b3395a5812a8e89e7f56bb0b702468e5ae0852a2fcd402",
		CircuitHash: "5f5c5748f35aea83eaac49b2b7f01b6e3cef842b4b4564961e60442873142265",
		Prover:      &AESProver{},
	},
	"aes-256-ctr": {
		KeyHash:     "5461d6bb5ec52fe8ddc8f2d9ae92f71561defc2d697f71801981edd4707e0519",
		CircuitHash: "ba7cd2f17886cd68017e317887a3fc4743fa51daf2e932d8d9905b54c15abf95",
		Prover:      &AESProver{},
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
	zerolog.SetGlobalLevel(zerolog.Disabled)
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

		// inHash := sha256.Sum256(provingKey)
		// keyHash := mustHex(proverParams.KeyHash)

		/*if subtle.ConstantTimeCompare(inHash[:], keyHash) != 1 {
			fmt.Println("incorrect hash")
			return false
		}*/

		pkey := groth16.NewProvingKey(ecc.BN254)
		_, err := pkey.ReadFrom(bytes.NewBuffer(provingKey))
		if err != nil {
			fmt.Println(fmt.Errorf("error reading proving key: %v", err))
			return false
		}

		var r1cs constraint.ConstraintSystem
		// inHash = sha256.Sum256(r1csData)
		// circuitHash := mustHex(proverParams.CircuitHash)

		/*if subtle.ConstantTimeCompare(inHash[:], circuitHash) != 1 {
			fmt.Println(fmt.Errorf("circuit hash mismatch"))
			return false
		}*/

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
