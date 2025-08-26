package libraries

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	"gnark-symmetric-crypto/circuits/toprf"
	prover "gnark-symmetric-crypto/libraries/prover/impl"
	oprf2 "gnark-symmetric-crypto/libraries/prover/oprf"
	verifier "gnark-symmetric-crypto/libraries/verifier/impl"
	"gnark-symmetric-crypto/libraries/verifier/oprf"
	"gnark-symmetric-crypto/utils"
	"math"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/chacha20"
)

var chachaKey, aes128Key, aes256Key, chachaOprfKey, aes128OprfKey, aes256OprfKey,
	chachaR1CS, aes128r1cs, aes256r1cs, chachaOprfr1cs, aes128Oprfr1cs, aes256Oprfr1cs []byte

const CHACHA20_BLOCKS = 2

func init() {
	chachaKey, _ = fetchFile("pk.chacha20")
	aes128Key, _ = fetchFile("pk.aes128")
	aes256Key, _ = fetchFile("pk.aes256")
	chachaOprfKey, _ = fetchFile("pk.chacha20_oprf")
	aes128OprfKey, _ = fetchFile("pk.aes128_oprf")
	aes256OprfKey, _ = fetchFile("pk.aes256_oprf")

	chachaR1CS, _ = fetchFile("r1cs.chacha20")
	aes128r1cs, _ = fetchFile("r1cs.aes128")
	aes256r1cs, _ = fetchFile("r1cs.aes256")
	chachaOprfr1cs, _ = fetchFile("r1cs.chacha20_oprf")
	aes128Oprfr1cs, _ = fetchFile("r1cs.aes128_oprf")
	aes256Oprfr1cs, _ = fetchFile("r1cs.aes256_oprf")
}

func TestInit(t *testing.T) {
	assert := test.NewAssert(t)

	wg1 := &sync.WaitGroup{}
	wg1.Add(1)

	wg2 := &sync.WaitGroup{}
	wg2.Add(24)

	f := func(algorithmID uint8, provingKey []byte, r1csData []byte) {
		go func() {
			wg1.Wait()
			assert.True(prover.InitAlgorithm(algorithmID, provingKey, r1csData))
			wg2.Done()
		}()
	}

	f(prover.CHACHA20, chachaKey, chachaR1CS)
	f(prover.AES_128, aes128Key, aes128r1cs)
	f(prover.AES_256, aes256Key, aes256r1cs)
	f(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs)
	f(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs)
	f(prover.AES_256_OPRF, aes256OprfKey, aes256Oprfr1cs)
	f(prover.CHACHA20, chachaKey, chachaR1CS)
	f(prover.AES_128, aes128Key, aes128r1cs)
	f(prover.AES_256, aes256Key, aes256r1cs)
	f(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs)
	f(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs)
	f(prover.AES_256_OPRF, aes256OprfKey, aes256Oprfr1cs)
	f(prover.CHACHA20, chachaKey, chachaR1CS)
	f(prover.AES_128, aes128Key, aes128r1cs)
	f(prover.AES_256, aes256Key, aes256r1cs)
	f(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs)
	f(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs)
	f(prover.AES_256_OPRF, aes256OprfKey, aes256Oprfr1cs)
	f(prover.CHACHA20, chachaKey, chachaR1CS)
	f(prover.AES_128, aes128Key, aes128r1cs)
	f(prover.AES_256, aes256Key, aes256r1cs)
	f(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs)
	f(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs)
	f(prover.AES_256_OPRF, aes256OprfKey, aes256Oprfr1cs)
	wg1.Done()
	wg2.Wait()
}

func TestPanic(t *testing.T) {
	assert := test.NewAssert(t)
	params := `{"cipher":"aes-256-ctr1","key":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"nonce":[0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"counter":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0],"input":[0,0,1,0,1,1,0,1,1,0,0,0,1,0,0,1,0,1,0,1,1,1,1,1,1,0,0,0,0,0,1,1,1,1,0,0,1,1,0,1,0,0,1,0,0,1,1,0,1,1,1,1,0,1,0,1,0,0,1,0,0,0,1,0,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,1,1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,0,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,1,1,0,1,0,0,0,0,1,1,0,1,0,1,0,0,0,1,0,1,1,0,0,1,1,0,0,0,1,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,1,0,1,0,0,1,0,0,0,0,1,1,1,1,0,0,1,0,0,0,0,1,1,1,1,0,1,0,0,1,0,0,0,0,0,1,1,1,0,0,1,1,1,0,0,0,0,0,0,0,1,1,1,0,0,1,0,1,0,0,0,1,0,0,0,0,0,1,0,1,0,1,1,0,1,0,0,1,0,1,0,0,1,0,1,1,0,1,0,1,0,1,0,0,1,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,1,1,1,0,0,0,0,0,0,1,1,0,0,1,0,1,1,1,0,0,1,0,1,1,1,1,0,0,0,1,0,1,0,1,0,0,1,1,1,0,0,1,0,0,1,0,1,1,0,1,1,0,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,1,1,0,1,1,0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	assert.Panics(func() {
		prover.Prove([]byte(params))
	})

	assert.False(verifier.Verify([]byte(`{"cipher":"chacha20"}`)))
}

func TestFullChaCha20(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS))
	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)
	bIn := make([]byte, 64*CHACHA20_BLOCKS)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bIn)

	// Create blocks with nonces and counters
	blocks := make([]prover.Block, CHACHA20_BLOCKS)
	for b := 0; b < CHACHA20_BLOCKS; b++ {
		blocks[b] = prover.Block{
			Nonce:   bNonce,
			Counter: counter + uint32(b),
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "chacha20",
		Key:    bKey,
		Blocks: blocks,
		Input:  bIn,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	// Create verifier blocks
	verifierBlocks := make([]verifier.Block, len(blocks))

	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
	}

	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
	}

	// Create the new JSON structure for public signals
	publicSignals := &verifier.PublicSignalsJSON{
		Ciphertext: outParams.Ciphertext,
		Blocks:     verifierBlocks,
		Input:      bIn,
	}

	publicSignalsJSON, err := json.Marshal(publicSignals)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignalsJSON,
	}
	inBuf, err := json.Marshal(inParams)
	assert.NoError(err)
	assert.True(verifier.Verify(inBuf))
}

func TestFullAES256(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs))
	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)
	bPt := make([]byte, aes_v2.BLOCKS*16)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bPt)

	// Create blocks with nonces and counters
	blocks := make([]prover.Block, aes_v2.BLOCKS)
	for b := 0; b < aes_v2.BLOCKS; b++ {
		blocks[b] = prover.Block{
			Nonce:   bNonce,
			Counter: counter + uint32(b),
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "aes-256-ctr",
		Key:    bKey,
		Blocks: blocks,
		Input:  bPt,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	// Create verifier blocks
	verifierBlocks := make([]verifier.Block, len(blocks))

	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
	}

	// Create the new JSON structure for public signals
	publicSignals := &verifier.PublicSignalsJSON{
		Ciphertext: outParams.Ciphertext,
		Blocks:     verifierBlocks,
		Input:      bPt,
	}

	publicSignalsJSON, err := json.Marshal(publicSignals)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignalsJSON,
	}
	inBuf, _ := json.Marshal(inParams)

	assert.True(verifier.Verify(inBuf))
}

func TestFullAES128(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs))
	bKey := make([]byte, 16)
	bNonce := make([]byte, 12)
	bPt := make([]byte, aes_v2.BLOCKS*16)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bPt)

	// Create blocks with nonces and counters
	blocks := make([]prover.Block, aes_v2.BLOCKS)
	for b := 0; b < aes_v2.BLOCKS; b++ {
		blocks[b] = prover.Block{
			Nonce:   bNonce,
			Counter: counter + uint32(b),
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "aes-128-ctr",
		Key:    bKey,
		Blocks: blocks,
		Input:  bPt,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	// Create verifier blocks
	verifierBlocks := make([]verifier.Block, len(blocks))

	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
	}

	// Create the new JSON structure for public signals
	publicSignals := &verifier.PublicSignalsJSON{
		Ciphertext: outParams.Ciphertext,
		Blocks:     verifierBlocks,
		Input:      bPt,
	}

	publicSignalsJSON, err := json.Marshal(publicSignals)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignalsJSON,
	}
	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

func TestFullChaCha20OPRF(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs))
	bKey := make([]byte, 32)
	rand.Read(bKey)

	// Step 1: Create a 74-byte plaintext slice
	plaintext := make([]byte, 74)
	rand.Read(plaintext) // Initialize with random data

	// Place 14-byte email at position 2 (0-based)
	email := "test@email.com"
	emailBytes := []byte(email)
	copy(plaintext[2:], emailBytes) // Email at positions 2-15

	// Step 2: Encrypt first 10 bytes with one nonce/counter
	bNonce1 := make([]byte, 12)
	rand.Read(bNonce1)
	counter1 := uint32(10) // Counter 10 as specified

	cipher1, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce1)
	assert.NoError(err)
	cipher1.SetCounter(counter1)

	ciphertext1 := make([]byte, 10)
	cipher1.XORKeyStream(ciphertext1, plaintext[:10])

	// Step 3: Encrypt last 64 bytes with different nonce/counter
	bNonce2 := make([]byte, 12)
	rand.Read(bNonce2)
	counter2 := uint32(0) // Counter 0 as specified

	cipher2, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce2)
	assert.NoError(err)
	cipher2.SetCounter(counter2)

	ciphertext2 := make([]byte, 64)
	cipher2.XORKeyStream(ciphertext2, plaintext[10:])

	// Now we have:
	// - plaintext: 74 bytes total with email at positions 2-15
	// - ciphertext1: first 10 bytes encrypted (contains email bytes 2-9)
	// - ciphertext2: last 64 bytes encrypted (contains email bytes 10-15 at start)

	// Create the actual ciphertext (74 bytes total, no padding)
	// The prover should handle padding based on boundaries
	ciphertext := make([]byte, 74)
	copy(ciphertext[:10], ciphertext1)
	copy(ciphertext[10:], ciphertext2)

	// Debug: Print where email actually is
	t.Logf("Email in plaintext at positions 2-15: %s", plaintext[2:16])
	t.Logf("Email part 1 (pos 2-9): %s", plaintext[2:10])
	t.Logf("Email part 2 (pos 10-15): %s", plaintext[10:16])

	// Test the bitmask function to see what it's setting
	// We'll check this after the test runs to avoid import issues

	domainSeparator := "reclaim"

	// TOPRF setup

	threshold := toprf.Threshold
	nodes := threshold + 1

	tParams := &oprf.InputGenerateParams{
		Total: uint8(nodes),
	}

	btParams, err := json.Marshal(tParams)
	assert.NoError(err)

	bShares := oprf.TOPRFGenerateThresholdKeys(btParams)

	var shares *oprf.OutputGenerateParams
	err = json.Unmarshal(bShares, &shares)
	assert.NoError(err)

	req, err := utils.OPRFGenerateRequest(emailBytes, domainSeparator)
	assert.NoError(err)

	// TOPRF requests
	idxs := utils.PickRandomIndexes(nodes, threshold)

	responses := make([]*prover.TOPRFResponse, threshold)

	for i := 0; i < threshold; i++ {
		sk := new(big.Int).SetBytes(shares.Shares[idxs[i]].PrivateKey)
		evalResult, err := utils.OPRFEvaluate(sk, req.MaskedData)
		assert.NoError(err)

		resp := &prover.TOPRFResponse{
			Index:          uint8(idxs[i]),
			PublicKeyShare: shares.Shares[idxs[i]].PublicKey,
			Evaluated:      evalResult.EvaluatedPoint.Marshal(),
			C:              evalResult.C.Bytes(),
			R:              evalResult.R.Bytes(),
		}
		responses[i] = resp
	}

	elements := make([]*twistededwards.PointAffine, threshold)
	for i := 0; i < threshold; i++ {
		elements[i] = &twistededwards.PointAffine{}
		err = elements[i].Unmarshal(responses[i].Evaluated)
		assert.NoError(err)
	}

	finReq := &oprf2.InputTOPRFFinalizeParams{
		ServerPublicKey: shares.PublicKey,
		Request: &oprf2.OPRFRequest{
			Mask:           req.Mask.Bytes(),
			MaskedData:     req.MaskedData.Marshal(),
			SecretElements: [][]byte{req.SecretElements[0].Bytes(), req.SecretElements[1].Bytes()},
		},
		Responses: []*oprf2.OPRFResponse{
			{
				Index:          responses[0].Index,
				PublicKeyShare: responses[0].PublicKeyShare,
				Evaluated:      responses[0].Evaluated,
				C:              responses[0].C,
				R:              responses[0].R,
			},
		},
	}

	finReqJSON, _ := json.Marshal(finReq)
	finResp := oprf2.TOPRFFinalize(finReqJSON)
	var out *oprf2.OutputOPRFResponseParams
	err = json.Unmarshal(finResp, &out)
	assert.NoError(err)

	// Create blocks with nonces, counters, and boundaries for incomplete block handling
	blocks := make([]prover.Block, CHACHA20_BLOCKS)

	// Block 0: uses bNonce1 and counter1, has 10 bytes of actual data
	blocks[0] = prover.Block{
		Nonce:    bNonce1,
		Counter:  counter1,
		Boundary: 10, // First block has only 10 bytes of actual data
	}

	// Block 1: uses bNonce2 and counter2, has full 64 bytes
	blocks[1] = prover.Block{
		Nonce:   bNonce2,
		Counter: counter2,
		// No boundary means full block (64 bytes)
	}

	inputParams := &prover.InputParams{
		Cipher: "chacha20-toprf",
		Key:    bKey,
		Blocks: blocks,
		Input:  ciphertext, // Send only 74 bytes, prover should handle padding
		TOPRF: &prover.TOPRFParams{
			Pos:             2, // Email starts at logical position 2
			Len:             uint32(len(emailBytes)),
			Mask:            req.Mask.Bytes(),
			DomainSeparator: []byte(domainSeparator),
			Output:          out.Output,
			Responses:       responses,
		},
	}

	buf, err := json.Marshal(inputParams)
	assert.NoError(err)
	fmt.Println(string(buf))
	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	err = json.Unmarshal(res, &outParams)

	// Create verifier blocks
	verifierBlocks := make([]verifier.Block, len(blocks))
	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
		// Copy boundary information if it exists
		if b.Boundary != 0 {
			boundary := b.Boundary
			verifierBlocks[i].Boundary = &boundary
		}
	}
	assert.NoError(err)

	verifyResponses := make([]*verifier.TOPRFResponse, threshold)
	for i := 0; i < threshold; i++ {
		r := responses[i]
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
		Input:  ciphertext, // Send only 74 bytes, verifier should handle padding
		TOPRF: &verifier.TOPRFParams{
			Pos:             2, // Email starts at logical position 2
			Len:             uint32(len(emailBytes)),
			DomainSeparator: []byte(domainSeparator),
			Output:          out.Output,
			Responses:       verifyResponses,
		},
	}

	publicSignals, err := json.Marshal(oprfParams)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignals,
	}
	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

func TestFullAES128OPRF(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs))
	bKey := make([]byte, 16)
	rand.Read(bKey)

	// Create a realistic scenario with incomplete blocks
	// Block 0: 16 bytes (full)
	// Block 1: 16 bytes (full)
	// Block 2: 10 bytes (incomplete)
	// Block 3: 16 bytes (full)
	// Block 4: 16 bytes (full)
	// Total logical data: 16 + 16 + 10 + 16 + 16 = 74 bytes

	plaintext := make([]byte, 74)
	rand.Read(plaintext)

	email := "test@email.com"
	emailBytes := []byte(email)
	domainSeparator := "reclaim"

	// Place email at position 30 (will span blocks 1, 2, and 3)
	// Block 1: bytes 16-31 (positions 30-31 contain first 2 bytes of email)
	// Block 2: bytes 32-41 (positions 32-41 contain next 10 bytes of email)
	// Block 3: bytes 42-57 (positions 42-43 contain last 2 bytes of email)
	pos := uint32(30)
	copy(plaintext[pos:], emailBytes)

	// Create 5 different nonces and counters for each block
	nonces := make([][]byte, 5)
	counters := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		nonces[i] = make([]byte, 12)
		rand.Read(nonces[i])
		tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
		counters[i] = uint32(tmp.Uint64())
	}

	// Encrypt each block with its own nonce/counter
	ciphertexts := make([][]byte, 5)
	boundaries := []uint32{16, 16, 10, 16, 16}
	logicalPos := uint32(0)

	for i := 0; i < 5; i++ {
		blockSize := boundaries[i]
		blockPlaintext := plaintext[logicalPos : logicalPos+blockSize]

		block, err := aes.NewCipher(bKey)
		assert.NoError(err)
		ctr := cipher.NewCTR(block, append(nonces[i], binary.BigEndian.AppendUint32(nil, counters[i])...))

		ciphertexts[i] = make([]byte, blockSize)
		ctr.XORKeyStream(ciphertexts[i], blockPlaintext)

		logicalPos += blockSize
	}

	// Create the actual ciphertext (74 bytes total, no padding)
	// The prover should handle padding based on boundaries
	ciphertext := make([]byte, 74)
	offset := uint32(0)
	for i := 0; i < 5; i++ {
		copy(ciphertext[offset:], ciphertexts[i])
		offset += boundaries[i]
	}

	// Debug output
	t.Logf("Email at logical positions %d-%d: %s", pos, pos+14, string(plaintext[pos:pos+14]))
	t.Logf("Block 1 contains: %s", string(plaintext[30:32]))
	t.Logf("Block 2 contains: %s", string(plaintext[32:42]))
	t.Logf("Block 3 contains: %s", string(plaintext[42:44]))

	// TOPRF setup

	threshold := toprf.Threshold
	nodes := threshold + 1

	tParams := &oprf.InputGenerateParams{
		Total: uint8(nodes),
	}

	btParams, err := json.Marshal(tParams)
	assert.NoError(err)

	bShares := oprf.TOPRFGenerateThresholdKeys(btParams)

	var shares *oprf.OutputGenerateParams
	err = json.Unmarshal(bShares, &shares)
	assert.NoError(err)

	req, err := utils.OPRFGenerateRequest(emailBytes, domainSeparator)
	assert.NoError(err)

	// TOPRF requests
	idxs := utils.PickRandomIndexes(nodes, threshold)

	responses := make([]*prover.TOPRFResponse, threshold)

	for i := 0; i < threshold; i++ {
		sk := new(big.Int).SetBytes(shares.Shares[idxs[i]].PrivateKey)
		evalResult, err := utils.OPRFEvaluate(sk, req.MaskedData)
		assert.NoError(err)

		resp := &prover.TOPRFResponse{
			Index:          uint8(idxs[i]),
			PublicKeyShare: shares.Shares[idxs[i]].PublicKey,
			Evaluated:      evalResult.EvaluatedPoint.Marshal(),
			C:              evalResult.C.Bytes(),
			R:              evalResult.R.Bytes(),
		}
		responses[i] = resp
	}

	elements := make([]*twistededwards.PointAffine, threshold)
	for i := 0; i < threshold; i++ {
		elements[i] = &twistededwards.PointAffine{}
		err = elements[i].Unmarshal(responses[i].Evaluated)
		assert.NoError(err)
	}

	out, err := utils.TOPRFFinalize(idxs, elements, req.SecretElements, req.Mask)
	assert.NoError(err)

	// Create blocks array with nonces, counters, and boundaries for each block
	blocks := make([]prover.Block, aes_v2.BLOCKS)
	for b := 0; b < aes_v2.BLOCKS; b++ {
		blocks[b] = prover.Block{
			Nonce:   nonces[b],
			Counter: counters[b],
		}
		// Set boundaries for incomplete blocks
		if boundaries[b] != 16 {
			blocks[b].Boundary = boundaries[b]
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "aes-128-ctr-toprf",
		Key:    bKey,
		Blocks: blocks,
		Input:  ciphertext, // Send only 74 bytes, prover/verifier should handle padding
		TOPRF: &prover.TOPRFParams{
			Pos:             pos,
			Len:             uint32(len(emailBytes)),
			Mask:            req.Mask.Bytes(),
			DomainSeparator: []byte(domainSeparator),
			Output:          out.Bytes(),
			Responses:       responses,
		},
	}

	buf, err := json.Marshal(inputParams)
	assert.NoError(err)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	err = json.Unmarshal(res, &outParams)

	// Create verifier blocks with boundaries
	verifierBlocks := make([]verifier.Block, len(blocks))
	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
		// Copy boundary if it exists
		if b.Boundary != 0 {
			boundary := b.Boundary
			verifierBlocks[i].Boundary = &boundary
		}
	}
	assert.NoError(err)

	verifyResponses := make([]*verifier.TOPRFResponse, threshold)
	for i := 0; i < threshold; i++ {
		r := responses[i]
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
		Input:  ciphertext, // Send only 74 bytes, prover/verifier should handle padding
		TOPRF: &verifier.TOPRFParams{
			Pos:             pos,
			Len:             uint32(len(emailBytes)),
			DomainSeparator: []byte(domainSeparator),
			Output:          out.Bytes(),
			Responses:       verifyResponses,
		},
	}

	publicSignals, err := json.Marshal(oprfParams)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignals,
	}
	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}
func TestFullAES256OPRF(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_256_OPRF, aes256OprfKey, aes256Oprfr1cs))
	bKey := make([]byte, 32)
	rand.Read(bKey)

	// Create a realistic scenario with incomplete blocks
	// Block 0: 16 bytes (full)
	// Block 1: 16 bytes (full)
	// Block 2: 10 bytes (incomplete)
	// Block 3: 16 bytes (full)
	// Block 4: 16 bytes (full)
	// Total logical data: 16 + 16 + 10 + 16 + 16 = 74 bytes

	plaintext := make([]byte, 74)
	rand.Read(plaintext)

	email := "test@email.com"
	emailBytes := []byte(email)
	domainSeparator := "reclaim"

	// Place email at position 30 (will span blocks 1, 2, and 3)
	// Block 1: bytes 16-31 (positions 30-31 contain first 2 bytes of email)
	// Block 2: bytes 32-41 (positions 32-41 contain next 10 bytes of email)
	// Block 3: bytes 42-57 (positions 42-43 contain last 2 bytes of email)
	pos := uint32(30)
	copy(plaintext[pos:], emailBytes)

	// Create 5 different nonces and counters for each block
	nonces := make([][]byte, 5)
	counters := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		nonces[i] = make([]byte, 12)
		rand.Read(nonces[i])
		tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
		counters[i] = uint32(tmp.Uint64())
	}

	// Encrypt each block with its own nonce/counter
	ciphertexts := make([][]byte, 5)
	boundaries := []uint32{16, 16, 10, 16, 16}
	logicalPos := uint32(0)

	for i := 0; i < 5; i++ {
		blockSize := boundaries[i]
		blockPlaintext := plaintext[logicalPos : logicalPos+blockSize]

		block, err := aes.NewCipher(bKey)
		assert.NoError(err)
		ctr := cipher.NewCTR(block, append(nonces[i], binary.BigEndian.AppendUint32(nil, counters[i])...))

		ciphertexts[i] = make([]byte, blockSize)
		ctr.XORKeyStream(ciphertexts[i], blockPlaintext)

		logicalPos += blockSize
	}

	// Create the actual ciphertext (74 bytes total, no padding)
	// The prover should handle padding based on boundaries
	ciphertext := make([]byte, 74)
	offset := uint32(0)
	for i := 0; i < 5; i++ {
		copy(ciphertext[offset:], ciphertexts[i])
		offset += boundaries[i]
	}

	// Debug output
	t.Logf("Email at logical positions %d-%d: %s", pos, pos+14, string(plaintext[pos:pos+14]))
	t.Logf("Block 1 contains: %s", string(plaintext[30:32]))
	t.Logf("Block 2 contains: %s", string(plaintext[32:42]))
	t.Logf("Block 3 contains: %s", string(plaintext[42:44]))

	// TOPRF setup

	threshold := toprf.Threshold
	nodes := threshold + 1

	tParams := &oprf.InputGenerateParams{
		Total: uint8(nodes),
	}

	btParams, err := json.Marshal(tParams)
	assert.NoError(err)

	bShares := oprf.TOPRFGenerateThresholdKeys(btParams)

	var shares *oprf.OutputGenerateParams
	err = json.Unmarshal(bShares, &shares)
	assert.NoError(err)

	req, err := utils.OPRFGenerateRequest(emailBytes, domainSeparator)
	assert.NoError(err)

	// TOPRF requests
	idxs := utils.PickRandomIndexes(nodes, threshold)

	responses := make([]*prover.TOPRFResponse, threshold)

	for i := 0; i < threshold; i++ {
		sk := new(big.Int).SetBytes(shares.Shares[idxs[i]].PrivateKey)
		evalResult, err := utils.OPRFEvaluate(sk, req.MaskedData)
		assert.NoError(err)

		resp := &prover.TOPRFResponse{
			Index:          uint8(idxs[i]),
			PublicKeyShare: shares.Shares[idxs[i]].PublicKey,
			Evaluated:      evalResult.EvaluatedPoint.Marshal(),
			C:              evalResult.C.Bytes(),
			R:              evalResult.R.Bytes(),
		}
		responses[i] = resp
	}

	elements := make([]*twistededwards.PointAffine, threshold)
	for i := 0; i < threshold; i++ {
		elements[i] = &twistededwards.PointAffine{}
		err = elements[i].Unmarshal(responses[i].Evaluated)
		assert.NoError(err)
	}

	out, err := utils.TOPRFFinalize(idxs, elements, req.SecretElements, req.Mask)
	assert.NoError(err)

	// Create blocks array with nonces, counters, and boundaries for each block
	blocks := make([]prover.Block, aes_v2.BLOCKS)
	for b := 0; b < aes_v2.BLOCKS; b++ {
		blocks[b] = prover.Block{
			Nonce:   nonces[b],
			Counter: counters[b],
		}
		// Set boundaries for incomplete blocks
		if boundaries[b] != 16 {
			blocks[b].Boundary = boundaries[b]
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "aes-256-ctr-toprf",
		Key:    bKey,
		Blocks: blocks,
		Input:  ciphertext, // Send only 74 bytes, prover/verifier should handle padding
		TOPRF: &prover.TOPRFParams{
			Pos:             pos,
			Len:             uint32(len(emailBytes)),
			Mask:            req.Mask.Bytes(),
			DomainSeparator: []byte(domainSeparator),
			Output:          out.Bytes(),
			Responses:       responses,
		},
	}

	buf, err := json.Marshal(inputParams)
	assert.NoError(err)
	fmt.Println(string(buf))
	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	err = json.Unmarshal(res, &outParams)

	// Create verifier blocks with boundaries
	verifierBlocks := make([]verifier.Block, len(blocks))
	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
		// Copy boundary if it exists
		if b.Boundary != 0 {
			boundary := b.Boundary
			verifierBlocks[i].Boundary = &boundary
		}
	}
	assert.NoError(err)

	verifyResponses := make([]*verifier.TOPRFResponse, threshold)
	for i := 0; i < threshold; i++ {
		r := responses[i]
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
		Input:  ciphertext, // Send only 74 bytes, prover/verifier should handle padding
		TOPRF: &verifier.TOPRFParams{
			Pos:             pos,
			Len:             uint32(len(emailBytes)),
			DomainSeparator: []byte(domainSeparator),
			Output:          out.Bytes(),
			Responses:       verifyResponses,
		},
	}

	publicSignals, err := json.Marshal(oprfParams)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignals,
	}
	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

func Benchmark_ProveAES128(b *testing.B) {
	prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs)

	// Generate proper test data
	bKey := make([]byte, 16)
	bNonce := make([]byte, 12)
	bPt := make([]byte, aes_v2.BLOCKS*16)
	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bPt)

	blocks := make([]prover.Block, aes_v2.BLOCKS)
	for i := 0; i < aes_v2.BLOCKS; i++ {
		blocks[i] = prover.Block{
			Nonce:   bNonce,
			Counter: uint32(298071680 + i),
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "aes-128-ctr",
		Key:    bKey,
		Blocks: blocks,
		Input:  bPt,
	}

	params, _ := json.Marshal(inputParams)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prover.Prove(params)
	}
	b.ReportAllocs()
}

func Benchmark_ProveAES256(b *testing.B) {
	prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs)

	// Generate proper test data
	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)
	bPt := make([]byte, aes_v2.BLOCKS*16)
	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bPt)

	blocks := make([]prover.Block, aes_v2.BLOCKS)
	for i := 0; i < aes_v2.BLOCKS; i++ {
		blocks[i] = prover.Block{
			Nonce:   bNonce,
			Counter: uint32(2841725616 + i),
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "aes-256-ctr",
		Key:    bKey,
		Blocks: blocks,
		Input:  bPt,
	}

	params, _ := json.Marshal(inputParams)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prover.Prove(params)
	}
	b.ReportAllocs()
}

func Benchmark_ProveChacha(b *testing.B) {
	prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS)

	// Generate proper test data
	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)
	bIn := make([]byte, 64*CHACHA20_BLOCKS)
	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bIn)

	blocks := make([]prover.Block, CHACHA20_BLOCKS)
	for i := 0; i < CHACHA20_BLOCKS; i++ {
		blocks[i] = prover.Block{
			Nonce:   bNonce,
			Counter: uint32(1757507854 + i),
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "chacha20",
		Key:    bKey,
		Blocks: blocks,
		Input:  bIn,
	}

	params, _ := json.Marshal(inputParams)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prover.Prove(params)
	}
	b.ReportAllocs()
}

func Benchmark_ProveAES128OPRF(b *testing.B) {
	prover.InitAlgorithm(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs)

	// Use pre-generated valid OPRF params from TestFullAES128OPRF for consistency
	// AES has 5 blocks, each needs its own nonce and counter
	params := `{"cipher":"aes-128-ctr-toprf","key":"ZAWxNb2AdgO39yzI14XsZA==","nonces":["LBsTWdRfQ2J7unF2","LBsTWdRfQ2J7unF2","LBsTWdRfQ2J7unF2","LBsTWdRfQ2J7unF2","LBsTWdRfQ2J7unF2"],"counters":[2260824246,2260824247,2260824248,2260824249,2260824250],"input":"UTnKUAkCBrEYiC2tPMnGliYTdcbVFXrFhFRH3m3N5zl5XUhfljrNTdquVVeL2PleSc3w5m2ZI6kVePRaC/OWC8tQjwk4n7WpB8D4IpqQHSU=","toprf":{"pos":12,"len":14,"mask":"A1BXFdPv8/KMIWHKi5ayD+Ngj2x8CEqPIXaS94kBNxg=","domainSeparator":"cmVjbGFpbQ==","output":"IShCRuW+UON6xy/va104/4qxauCxbF/boK4SjbExTMM=","responses":[{"index":0,"publicKeyShare":"n/wRU9Jw6bMF/f+IwhF3SJmBQ9IevOCcNu6HOGV7NQg=","evaluated":"KhzfVQOJZfu7tacCPV82IzgmZsl9m4g931kTPvmg16Q=","c":"LeUBWWxMeLTK201i0QcyFEguuBwHOIkgWyebJHb4KuY=","r":"ATMhm3RUePybiYqj+dGM8OssXZPpkGXVeiNdoxKHhLY="}]}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveAES256OPRF(b *testing.B) {
	prover.InitAlgorithm(prover.AES_256_OPRF, aes256OprfKey, aes256Oprfr1cs)

	// Use pre-generated valid OPRF params from TestFullAES256OPRF for consistency
	// AES has 5 blocks, each needs its own nonce and counter
	params := `{"cipher":"aes-256-ctr-toprf","key":"ZcfBBYo05Zazg0QLFNnhuyuTs89PCyEKjSyubArwBJY=","blocks":[{"nonce":"6HkkH2CYhmEkr51J","counter":2442948417},{"nonce":"Ays3X8rBvnT8E4Lx","counter":1229436154},{"nonce":"fp6V8aOMjqbvARFH","counter":1770665406,"boundary":10},{"nonce":"ut7k4kP2B98WkyPk","counter":4151407847},{"nonce":"M2UnQwP6ZIoSSC4I","counter":2570170283}],"input":"kjndRePygzSMWiHHJO+OauJ96XSQOBaS0763gt454QWOAYbzUvUP4kVZAAAAAAAAWp0oZFUSt3dDdEmtNRbRn67k0GKiGzIE3k1l+I5VZxs=","toprf":{"pos":30,"len":14,"mask":"A3a+NorbwKAsYu/NQXXXiu4vTYL1Gz1XhTOT72rcYCk=","domainSeparator":"cmVjbGFpbQ==","output":"JwbwFcto0Ye3pldeCHCqA9jxCdHg1M7D3mysbGGFCgo=","responses":[{"index":1,"publicKeyShare":"inXkhLQjIXr50W0yKtw9qjYsZCypnpI3BNCNHUOdIiU=","evaluated":"OiPlX8Spp8QRW41VgPdsM6U5nC1njYlTsudvDCZR5SQ=","c":"JW/87LSNE1Xx4f303Wuwzjk9Mx83YSwy82OQuGfkfKc=","r":"BAr58yr/dTgMIfHXl3+Kr+D9zw8CaWwQDBs9TuNXQT0="}]}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveChachaOPRF(b *testing.B) {
	prover.InitAlgorithm(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs)

	// Use pre-generated valid OPRF params from TestFullChaCha20OPRF for consistency
	// ChaCha has 2 blocks, each needs its own nonce and counter
	params := `{"cipher":"chacha20-toprf","key":"Ka3Qs7LgwGaRQwIXYSQKYF1bpKX7BntH1+gbgiMHyYM=","nonces":["yLApW3mIK0mM3uE9","yLApW3mIK0mM3uE9"],"counters":[4168221410,4168221411],"input":"zDdyXezLpcexVGYoZoyuFIDjpXZCV+YSVbDd5SfRHge7HEril7C0gnqR7dPbMwj/2t9g5mU4x/2bvl+grkeyUT33HCyRvebvAEfDkGENP5aO2MC71P7ynYGIAV7/4QbkflQRA9pdKOHfqCSEzd4GqNaaIKzF1/A6AHXuaeOOg5U=","toprf":{"pos":59,"len":14,"mask":"BIvVtZdOIiZSDWb1/sLKqoEXhx4mc4Kmv580KPbll3Q=","domainSeparator":"cmVjbGFpbQ==","output":"CUcueErhemKezndgP7vjGImvG8ua9104RJe8QhNcuOc=","responses":[{"index":0,"publicKeyShare":"0W07hZxwL42VhLULWKIkYDAuukzGBuCafqZVPTWPrq8=","evaluated":"JxObYdh6IlUR4+GV6Z1oBcWr5wEnWzuWUHX07gGQ+So=","c":"FUBwJawrBPQe3OJs6zLj4vpz2SEG4AU1Q6ucXIZrCyM=","r":"A8NG/ewWaCAef6Mowvq4XTgVtRRcRvaD6edkrsirUOw="}]}}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func BenchmarkTOPRFFinalize(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()
	params := []byte(`{"serverPublicKey":"1AsWETKEjyyP/KKc8VXeASqo67rPp4ghI+ckN4P+hpY=","request":{"mask":"ExSgc7SIf8Sdp79pAWLapP4Dy4f2/pBra1EUflkxxA==","maskedData":"Lhz/ZIkMjs/LjDmPKZ3+HcO7PEW3+9g7oEuPNVs0o60=","secretElements":["bW9jLmxpYW1lQHRzZXQ=",""]},"responses":[{"index":1,"publicKeyShare":"1AsWETKEjyyP/KKc8VXeASqo67rPp4ghI+ckN4P+hpY=","evaluated":"+6zvgjZXtSYawia63IQoLM9pHa2Mru5W0iz7nfG1+ho=","c":"DeuKN5pxLeBZmshi2qgyb71gGBwY0o/UzGVYuHxvFI0=","r":"D3d9qGrXgMCannDhD99V7EkIpy/hhpCm/kzvhvp+3A=="}]}`)
	for i := 0; i < b.N; i++ {
		oprf2.TOPRFFinalize(params)
	}
}

func TestChaCha20RandomNoncesCounters(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS))
	bKey := make([]byte, 32)
	bIn := make([]byte, 64*CHACHA20_BLOCKS)

	rand.Read(bKey)
	rand.Read(bIn)

	// Create truly random nonces and counters for each block
	blocks := make([]prover.Block, CHACHA20_BLOCKS)
	for b := 0; b < CHACHA20_BLOCKS; b++ {
		nonce := make([]byte, 12)
		rand.Read(nonce)
		tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
		counter := uint32(tmp.Uint64())
		blocks[b] = prover.Block{
			Nonce:   nonce,
			Counter: counter,
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "chacha20",
		Key:    bKey,
		Blocks: blocks,
		Input:  bIn,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	// Create verifier blocks
	verifierBlocks := make([]verifier.Block, len(blocks))

	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
	}

	// Create the new JSON structure for public signals
	publicSignals := &verifier.PublicSignalsJSON{
		Ciphertext: outParams.Ciphertext,
		Blocks:     verifierBlocks,
		Input:      bIn,
	}

	publicSignalsJSON, err := json.Marshal(publicSignals)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignalsJSON,
	}
	inBuf, err := json.Marshal(inParams)
	assert.NoError(err)
	assert.True(verifier.Verify(inBuf))
}

func TestAES128RandomNoncesCounters(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs))
	bKey := make([]byte, 16)
	bPt := make([]byte, aes_v2.BLOCKS*16)

	rand.Read(bKey)
	rand.Read(bPt)

	// Create truly random nonces and counters for each block
	blocks := make([]prover.Block, aes_v2.BLOCKS)
	for b := 0; b < aes_v2.BLOCKS; b++ {
		nonce := make([]byte, 12)
		rand.Read(nonce)
		tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
		counter := uint32(tmp.Uint64())
		blocks[b] = prover.Block{
			Nonce:   nonce,
			Counter: counter,
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "aes-128-ctr",
		Key:    bKey,
		Blocks: blocks,
		Input:  bPt,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	// Create verifier blocks
	verifierBlocks := make([]verifier.Block, len(blocks))

	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
	}

	// Create the new JSON structure for public signals
	publicSignals := &verifier.PublicSignalsJSON{
		Ciphertext: outParams.Ciphertext,
		Blocks:     verifierBlocks,
		Input:      bPt,
	}

	publicSignalsJSON, err := json.Marshal(publicSignals)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignalsJSON,
	}
	inBuf, err := json.Marshal(inParams)
	assert.NoError(err)
	assert.True(verifier.Verify(inBuf))
}

func TestAES256RandomNoncesCounters(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs))
	bKey := make([]byte, 32)
	bPt := make([]byte, aes_v2.BLOCKS*16)

	rand.Read(bKey)
	rand.Read(bPt)

	// Create truly random nonces and counters for each block
	blocks := make([]prover.Block, aes_v2.BLOCKS)
	for b := 0; b < aes_v2.BLOCKS; b++ {
		nonce := make([]byte, 12)
		rand.Read(nonce)
		tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
		counter := uint32(tmp.Uint64())
		blocks[b] = prover.Block{
			Nonce:   nonce,
			Counter: counter,
		}
	}

	inputParams := &prover.InputParams{
		Cipher: "aes-256-ctr",
		Key:    bKey,
		Blocks: blocks,
		Input:  bPt,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	// Create verifier blocks
	verifierBlocks := make([]verifier.Block, len(blocks))

	for i, b := range blocks {
		verifierBlocks[i] = verifier.Block{
			Nonce:   b.Nonce,
			Counter: b.Counter,
		}
	}

	// Create the new JSON structure for public signals
	publicSignals := &verifier.PublicSignalsJSON{
		Ciphertext: outParams.Ciphertext,
		Blocks:     verifierBlocks,
		Input:      bPt,
	}

	publicSignalsJSON, err := json.Marshal(publicSignals)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignalsJSON,
	}
	inBuf, err := json.Marshal(inParams)
	assert.NoError(err)
	assert.True(verifier.Verify(inBuf))
}

func fetchFile(keyName string) ([]byte, error) {
	f, err := os.ReadFile("../../resources/gnark/" + keyName)
	if err != nil {
		panic(err)
	}
	return f, nil
}
