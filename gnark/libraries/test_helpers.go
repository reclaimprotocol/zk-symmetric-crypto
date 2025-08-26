package libraries

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"

	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	chachaV3 "gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/circuits/toprf"
	prover "gnark-symmetric-crypto/libraries/prover/impl"
	verifier "gnark-symmetric-crypto/libraries/verifier/impl"
	"gnark-symmetric-crypto/libraries/verifier/oprf"
	"gnark-symmetric-crypto/utils"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/chacha20"
)

type CipherConfig struct {
	Name       string
	BlockSize  int
	BlockCount int
	KeySize    int
	TotalSize  int
	ProverKey  []byte
	R1CS       []byte
	Algorithm  int // prover algorithm constant
	IsOPRF     bool
}

var CipherConfigs = map[string]*CipherConfig{
	"chacha20": {
		Name:       "chacha20",
		BlockSize:  64,
		BlockCount: chachaV3.Blocks,
		KeySize:    32,
		TotalSize:  chachaV3.Blocks * 64,
		Algorithm:  prover.CHACHA20,
	},
	"chacha20-toprf": {
		Name:       "chacha20-toprf",
		BlockSize:  64,
		BlockCount: chachaV3.Blocks,
		KeySize:    32,
		TotalSize:  chachaV3.Blocks * 64,
		Algorithm:  prover.CHACHA20_OPRF,
		IsOPRF:     true,
	},
	"aes-128-ctr": {
		Name:       "aes-128-ctr",
		BlockSize:  16,
		BlockCount: aes_v2.BLOCKS,
		KeySize:    16,
		TotalSize:  aes_v2.BLOCKS * 16,
		Algorithm:  prover.AES_128,
	},
	"aes-128-ctr-toprf": {
		Name:       "aes-128-ctr-toprf",
		BlockSize:  16,
		BlockCount: aes_v2.BLOCKS,
		KeySize:    16,
		TotalSize:  aes_v2.BLOCKS * 16,
		Algorithm:  prover.AES_128_OPRF,
		IsOPRF:     true,
	},
	"aes-256-ctr": {
		Name:       "aes-256-ctr",
		BlockSize:  16,
		BlockCount: aes_v2.BLOCKS,
		KeySize:    32,
		TotalSize:  aes_v2.BLOCKS * 16,
		Algorithm:  prover.AES_256,
	},
	"aes-256-ctr-toprf": {
		Name:       "aes-256-ctr-toprf",
		BlockSize:  16,
		BlockCount: aes_v2.BLOCKS,
		KeySize:    32,
		TotalSize:  aes_v2.BLOCKS * 16,
		Algorithm:  prover.AES_256_OPRF,
		IsOPRF:     true,
	},
}

type TestData struct {
	Plaintext  []byte
	Ciphertext []byte
	Key        []byte
	Blocks     []prover.Block
	Boundaries []uint32
	Email      string
	EmailPos   uint32
}

// GenerateTestData creates test data with optional incomplete blocks
func GenerateTestData(t *testing.T, config *CipherConfig, withBoundaries bool) *TestData {
	td := &TestData{
		Key:   make([]byte, config.KeySize),
		Email: "test@email.com",
	}
	rand.Read(td.Key)

	if withBoundaries {
		// Create incomplete blocks scenario
		td.Boundaries = generateBoundaries(config)
		totalSize := uint32(0)
		for _, b := range td.Boundaries {
			totalSize += b
		}
		td.Plaintext = make([]byte, totalSize)
		rand.Read(td.Plaintext)

		// Place email at a position that spans blocks
		if config.BlockCount == 2 { // ChaCha
			td.EmailPos = 2
		} else { // AES
			td.EmailPos = 30
		}
		copy(td.Plaintext[td.EmailPos:], []byte(td.Email))

		td.Blocks = make([]prover.Block, config.BlockCount)
		td.Ciphertext = make([]byte, totalSize)

		// Encrypt with different nonces per block
		offset := uint32(0)
		for i := 0; i < config.BlockCount; i++ {
			nonce := make([]byte, 12)
			rand.Read(nonce)
			counter := randomCounter()

			td.Blocks[i] = prover.Block{
				Nonce:   nonce,
				Counter: counter,
			}
			if td.Boundaries[i] != uint32(config.BlockSize) {
				boundary := td.Boundaries[i]
				td.Blocks[i].Boundary = &boundary
			}

			blockSize := td.Boundaries[i]
			encryptBlock(td.Key, nonce, counter,
				td.Plaintext[offset:offset+blockSize],
				td.Ciphertext[offset:offset+blockSize],
				config)
			offset += blockSize
		}
	} else {
		// Standard full blocks
		td.Plaintext = make([]byte, config.TotalSize)
		rand.Read(td.Plaintext)

		// For standard tests, we don't need email or pre-encryption
		// The prover will encrypt the plaintext

		// Use same nonce for all blocks (legacy behavior)
		nonce := make([]byte, 12)
		rand.Read(nonce)
		counter := randomCounter()

		td.Blocks = make([]prover.Block, config.BlockCount)
		for i := 0; i < config.BlockCount; i++ {
			td.Blocks[i] = prover.Block{
				Nonce:   nonce,
				Counter: counter + uint32(i),
			}
		}

		// For standard tests, ciphertext will be computed by the prover
		td.Ciphertext = nil
	}

	return td
}

func generateBoundaries(config *CipherConfig) []uint32 {
	if config.BlockCount == 2 { // ChaCha
		return []uint32{10, 64} // First block incomplete
	}
	// AES - middle block incomplete
	boundaries := make([]uint32, config.BlockCount)
	for i := 0; i < config.BlockCount; i++ {
		if i == 2 {
			boundaries[i] = 10 // Middle block incomplete
		} else {
			boundaries[i] = uint32(config.BlockSize)
		}
	}
	return boundaries
}

func randomCounter() uint32 {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	return uint32(n.Uint64())
}

func encryptBlock(key []byte, nonce []byte, counter uint32, plaintext, ciphertext []byte, config *CipherConfig) {
	if config.Name == "chacha20" || config.Name == "chacha20-toprf" {
		c, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
		c.SetCounter(counter)
		c.XORKeyStream(ciphertext, plaintext)
	} else {
		block, _ := aes.NewCipher(key)
		ctr := cipher.NewCTR(block, append(nonce, binary.BigEndian.AppendUint32(nil, counter)...))
		ctr.XORKeyStream(ciphertext, plaintext)
	}
}

func encryptAll(key []byte, nonce []byte, counter uint32, plaintext, ciphertext []byte, config *CipherConfig) {
	if config.Name == "chacha20" || config.Name == "chacha20-toprf" {
		c, _ := chacha20.NewUnauthenticatedCipher(key, nonce)
		c.SetCounter(counter)
		c.XORKeyStream(ciphertext, plaintext)
	} else {
		block, _ := aes.NewCipher(key)
		ctr := cipher.NewCTR(block, append(nonce, binary.BigEndian.AppendUint32(nil, counter)...))
		ctr.XORKeyStream(ciphertext, plaintext)
	}
}

type OPRFData struct {
	Mask            []byte
	DomainSeparator string
	Output          []byte
	Responses       []*prover.TOPRFResponse
}

func GenerateOPRFData(t *testing.T, emailBytes []byte) *OPRFData {
	domainSeparator := "reclaim"
	threshold := toprf.Threshold
	nodes := threshold + 1

	// Generate threshold keys
	tParams := &oprf.InputGenerateParams{Total: uint8(nodes)}
	btParams, _ := json.Marshal(tParams)
	bShares := oprf.TOPRFGenerateThresholdKeys(btParams)
	var shares *oprf.OutputGenerateParams
	json.Unmarshal(bShares, &shares)

	// Generate OPRF request
	req, err := utils.OPRFGenerateRequest(emailBytes, domainSeparator)
	test.NewAssert(t).NoError(err)

	// Generate responses
	idxs := utils.PickRandomIndexes(nodes, threshold)
	responses := make([]*prover.TOPRFResponse, threshold)
	elements := make([]*twistededwards.PointAffine, threshold)

	for i := 0; i < threshold; i++ {
		sk := new(big.Int).SetBytes(shares.Shares[idxs[i]].PrivateKey)
		evalResult, _ := utils.OPRFEvaluate(sk, req.MaskedData)

		responses[i] = &prover.TOPRFResponse{
			Index:          uint8(idxs[i]),
			PublicKeyShare: shares.Shares[idxs[i]].PublicKey,
			Evaluated:      evalResult.EvaluatedPoint.Marshal(),
			C:              evalResult.C.Bytes(),
			R:              evalResult.R.Bytes(),
		}

		elements[i] = &twistededwards.PointAffine{}
		elements[i].Unmarshal(responses[i].Evaluated)
	}

	// Finalize OPRF
	out, _ := utils.TOPRFFinalize(idxs, elements, req.SecretElements, req.Mask)

	return &OPRFData{
		Mask:            req.Mask.Bytes(),
		DomainSeparator: domainSeparator,
		Output:          out.Bytes(),
		Responses:       responses,
	}
}

func RunFullTest(t *testing.T, config *CipherConfig, withBoundaries bool) {
	assert := test.NewAssert(t)

	// Initialize algorithm
	assert.True(prover.InitAlgorithm(uint8(config.Algorithm), config.ProverKey, config.R1CS))

	// Generate test data
	td := GenerateTestData(t, config, withBoundaries)

	// Prepare input params
	var inputData []byte
	if config.IsOPRF {
		inputData = td.Ciphertext // OPRF tests send ciphertext
	} else {
		inputData = td.Plaintext // Standard tests send plaintext
	}

	inputParams := &prover.InputParams{
		Cipher: config.Name,
		Key:    td.Key,
		Blocks: td.Blocks,
		Input:  inputData,
	}

	// Add OPRF data if needed
	if config.IsOPRF {
		emailBytes := []byte(td.Email)
		oprfData := GenerateOPRFData(t, emailBytes)
		inputParams.TOPRF = &prover.TOPRFParams{
			Pos:             td.EmailPos,
			Len:             uint32(len(emailBytes)),
			Mask:            oprfData.Mask,
			DomainSeparator: []byte(oprfData.DomainSeparator),
			Output:          oprfData.Output,
			Responses:       oprfData.Responses,
		}
	}

	// Generate proof
	buf, _ := json.Marshal(inputParams)
	res := prover.Prove(buf)
	assert.True(len(res) > 0)

	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	// Verify proof
	verifyTest(t, config, td, inputParams, outParams)
}

func verifyTest(t *testing.T, config *CipherConfig, td *TestData, inputParams *prover.InputParams, outParams *prover.OutputParams) {
	assert := test.NewAssert(t)

	// Create verifier blocks
	verifierBlocks := make([]verifier.Block, len(td.Blocks))
	for i, b := range td.Blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
		if b.Boundary != nil {
			verifierBlocks[i].Boundary = b.Boundary
		}
	}

	var publicSignals []byte
	var err error

	if config.IsOPRF {
		// Create OPRF verification params
		verifyResponses := make([]*verifier.TOPRFResponse, len(inputParams.TOPRF.Responses))
		for i, r := range inputParams.TOPRF.Responses {
			verifyResponses[i] = &verifier.TOPRFResponse{
				Index:          r.Index,
				PublicKeyShare: r.PublicKeyShare,
				Evaluated:      r.Evaluated,
				C:              r.C,
				R:              r.R,
			}
		}

		oprfParams := &verifier.InputTOPRFParams{
			Blocks: verifierBlocks,
			Input:  td.Ciphertext,
			TOPRF: &verifier.TOPRFParams{
				Pos:             inputParams.TOPRF.Pos,
				Len:             inputParams.TOPRF.Len,
				DomainSeparator: inputParams.TOPRF.DomainSeparator,
				Output:          inputParams.TOPRF.Output,
				Responses:       verifyResponses,
			},
		}
		publicSignals, err = json.Marshal(oprfParams)
	} else {
		// Standard verification params
		// For standard tests, prover outputs ciphertext
		publicSignalsJSON := &verifier.PublicSignalsJSON{
			Ciphertext: outParams.Ciphertext, // The ciphertext produced by prover
			Blocks:     verifierBlocks,
			Input:      td.Plaintext, // The original plaintext
		}
		publicSignals, err = json.Marshal(publicSignalsJSON)
	}

	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        config.Name,
		Proof:         outParams.Proof,
		PublicSignals: publicSignals,
	}

	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

// RunBenchmark runs a benchmark for the specified cipher configuration
func RunBenchmark(b *testing.B, config *CipherConfig) {
	// Initialize algorithm
	if !prover.InitAlgorithm(uint8(config.Algorithm), config.ProverKey, config.R1CS) {
		b.Fatal("Failed to initialize algorithm")
	}

	// Generate test data for standard (non-OPRF) benchmarks
	td := GenerateTestData(&testing.T{}, config, false)

	inputParams := &prover.InputParams{
		Cipher: config.Name,
		Key:    td.Key,
		Blocks: td.Blocks,
		Input:  td.Plaintext,
	}

	params, _ := json.Marshal(inputParams)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prover.Prove(params)
	}
	b.ReportAllocs()
}
