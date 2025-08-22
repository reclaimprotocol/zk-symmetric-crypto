package impl

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"sync"

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
		KeyHash:     "f269ac58118b4a79954f32c8e6d58c68d5c72d0dce36e6dd46a4848e65c9b386",
		CircuitHash: "c11b7336ffeb26092608276d0c6ae7942a5c20f6c67ef70eb89a33b12f068977",
		Prover:      &ChaChaProver{},
	},
	"aes-128-ctr": {
		KeyHash:     "a0e04ecf49fc6037e8352a390200bd0b40ae51068b9808c37f80037775dd7e7f",
		CircuitHash: "7cf164301b5a617c486bbf2df092d6fe1abfd47beccfa98a8c4c43560c055308",
		Prover:      &AESProver{},
	},
	"aes-256-ctr": {
		KeyHash:     "0dfec654916b2500ccec395728bed9fe286ab9a243ff18502f4fab9a5315eff6",
		CircuitHash: "ddf3af7839f9d3817fbf78f015849550246988c0801cafe77f7cb5b991e512e9",
		Prover:      &AESProver{},
	},
	"chacha20-toprf": {
		KeyHash:     "c25584633c828816e2307e7aa3eac042f478080ae3a0017e11b1f56b0ead0ca9",
		CircuitHash: "b2c3af85c96df80e7c51cd6a98ebdcfc107c9d30a2c8994638bd9b4ec2c2e9cb",
		Prover:      &ChaChaOPRFProver{},
	},
	"aes-128-ctr-toprf": {
		KeyHash:     "b4c7814af836253481bef13cc6fce271b2db2beb6fc93931cbae50dfd51efbd4",
		CircuitHash: "64a97900f132caa63bf3e97653e1d47e0df7a4026dcd201df3075c609e184d13",
		Prover:      &AESOPRFProver{},
	},
	"aes-256-ctr-toprf": {
		KeyHash:     "fc39b43894ca9ea3a6c28e5e9ade0b9b4b855e39004a7757fdc7e3bf8452a694",
		CircuitHash: "608d42ea0b3d4e840d0bfd86ca4a335885d097b7f8b8eba6788f20f260c06d0f",
		Prover:      &AESOPRFProver{},
	},
}

type OutputParams struct {
	Proof         []uint8 `json:"proof"`
	PublicSignals []uint8 `json:"publicSignals"`
}

type ProverParams struct {
	Prover
	KeyHash     string
	CircuitHash string
	initDone    bool
	initLock    sync.Mutex
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
		proverParams.initLock.Lock()
		defer proverParams.initLock.Unlock()
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
		fmt.Println("Initialized", alg)
		return true
	}
	return false
}

func Prove(params []byte) []byte {
	// First check if this contains "toprf" field to determine type
	var rawMap map[string]interface{}
	err := json.Unmarshal(params, &rawMap)
	if err != nil {
		panic(err)
	}

	if _, hasToprf := rawMap["toprf"]; hasToprf {
		// This is an OPRF proof - parse as InputOPRFParams
		var oprfParams *InputOPRFParams
		err = json.Unmarshal(params, &oprfParams)
		if err != nil {
			panic(err)
		}

		// Convert to internal format
		internalParams := convertOPRFToInternalParams(oprfParams)
		if prover, ok := provers[oprfParams.Cipher]; ok {
			if !prover.initDone {
				panic(fmt.Sprintf("proving params are not initialized for cipher: %s", oprfParams.Cipher))
			}
			proof, ciphertext := prover.Prove(internalParams)
			res, er := json.Marshal(&OutputParams{
				Proof:         proof,
				PublicSignals: ciphertext,
			})
			if er != nil {
				panic(er)
			}
			return res
		} else {
			panic("could not find prover for" + oprfParams.Cipher)
		}
	} else {
		// This is a non-OPRF proof - parse as InputParams
		var inputParams *InputParams
		err = json.Unmarshal(params, &inputParams)
		if err != nil {
			panic(err)
		}

		// Convert to internal format
		internalParams := convertToInternalParams(inputParams)
		if prover, ok := provers[inputParams.Cipher]; ok {
			if !prover.initDone {
				panic(fmt.Sprintf("proving params are not initialized for cipher: %s", inputParams.Cipher))
			}
			proof, ciphertext := prover.Prove(internalParams)
			res, er := json.Marshal(&OutputParams{
				Proof:         proof,
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
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Wrapper functions for backward compatibility with single nonce/counter API
// These functions internally create arrays for the circuit requirements

// Internal structure for provers (unchanged from original)
type internalInputParams struct {
	Cipher   string       `json:"cipher"`
	Key      []uint8      `json:"key"`
	Nonces   [][]uint8    `json:"nonces"`   // Array of nonces, one per block
	Counters []uint32     `json:"counters"` // Array of counters, one per block
	Input    []uint8      `json:"input"`    // usually it's redacted ciphertext
	TOPRF    *TOPRFParams `json:"toprf,omitempty"`
}

// Convert InputParams to internal format
func convertToInternalParams(params *InputParams) *internalInputParams {
	var numBlocks int
	switch params.Cipher {
	case "chacha20":
		numBlocks = chachaV3.Blocks
	case "aes-128-ctr", "aes-256-ctr":
		numBlocks = aes_v2.BLOCKS
	default:
		panic("unknown cipher: " + params.Cipher)
	}

	// Create arrays of nonces and counters for each block
	nonces := make([][]uint8, numBlocks)
	counters := make([]uint32, numBlocks)
	for b := 0; b < numBlocks; b++ {
		nonces[b] = params.Nonce
		counters[b] = params.Counter + uint32(b)
	}

	return &internalInputParams{
		Cipher:   params.Cipher,
		Key:      params.Key,
		Nonces:   nonces,
		Counters: counters,
		Input:    params.Input,
	}
}

// Convert InputOPRFParams to internal format
func convertOPRFToInternalParams(params *InputOPRFParams) *internalInputParams {
	return &internalInputParams{
		Cipher:   params.Cipher,
		Key:      params.Key,
		Nonces:   params.Nonces,
		Counters: params.Counters,
		Input:    params.Input,
		TOPRF:    params.TOPRF,
	}
}

// ProveChaCha20 proves ChaCha20 encryption with a single nonce and counter
// It internally duplicates the nonce and increments the counter for each block
func ProveChaCha20(key []byte, nonce []byte, counter uint32, input []byte) []byte {
	inputParams := &InputParams{
		Cipher:  "chacha20",
		Key:     key,
		Nonce:   nonce,
		Counter: counter,
		Input:   input,
	}

	buf, err := json.Marshal(inputParams)
	if err != nil {
		panic(err)
	}

	return Prove(buf)
}

// ProveAES128 proves AES-128-CTR encryption with a single nonce and counter
// It internally duplicates the nonce and increments the counter for each block
func ProveAES128(key []byte, nonce []byte, counter uint32, input []byte) []byte {
	inputParams := &InputParams{
		Cipher:  "aes-128-ctr",
		Key:     key,
		Nonce:   nonce,
		Counter: counter,
		Input:   input,
	}

	buf, err := json.Marshal(inputParams)
	if err != nil {
		panic(err)
	}

	return Prove(buf)
}

// ProveAES256 proves AES-256-CTR encryption with a single nonce and counter
// It internally duplicates the nonce and increments the counter for each block
func ProveAES256(key []byte, nonce []byte, counter uint32, input []byte) []byte {
	inputParams := &InputParams{
		Cipher:  "aes-256-ctr",
		Key:     key,
		Nonce:   nonce,
		Counter: counter,
		Input:   input,
	}

	buf, err := json.Marshal(inputParams)
	if err != nil {
		panic(err)
	}

	return Prove(buf)
}

// ProveChaCha20OPRF proves ChaCha20 encryption with TOPRF using arrays of nonces and counters
func ProveChaCha20OPRF(key []byte, nonces [][]uint8, counters []uint32, input []byte, toprf *TOPRFParams) []byte {
	inputParams := &InputOPRFParams{
		Cipher:   "chacha20-toprf",
		Key:      key,
		Nonces:   nonces,
		Counters: counters,
		Input:    input,
		TOPRF:    toprf,
	}

	buf, err := json.Marshal(inputParams)
	if err != nil {
		panic(err)
	}

	return Prove(buf)
}

// ProveAES128OPRF proves AES-128-CTR encryption with TOPRF using arrays of nonces and counters
func ProveAES128OPRF(key []byte, nonces [][]uint8, counters []uint32, input []byte, toprf *TOPRFParams) []byte {
	inputParams := &InputOPRFParams{
		Cipher:   "aes-128-ctr-toprf",
		Key:      key,
		Nonces:   nonces,
		Counters: counters,
		Input:    input,
		TOPRF:    toprf,
	}

	buf, err := json.Marshal(inputParams)
	if err != nil {
		panic(err)
	}

	return Prove(buf)
}

// ProveAES256OPRF proves AES-256-CTR encryption with TOPRF using arrays of nonces and counters
func ProveAES256OPRF(key []byte, nonces [][]uint8, counters []uint32, input []byte, toprf *TOPRFParams) []byte {
	inputParams := &InputOPRFParams{
		Cipher:   "aes-256-ctr-toprf",
		Key:      key,
		Nonces:   nonces,
		Counters: counters,
		Input:    input,
		TOPRF:    toprf,
	}

	buf, err := json.Marshal(inputParams)
	if err != nil {
		panic(err)
	}

	return Prove(buf)
}
