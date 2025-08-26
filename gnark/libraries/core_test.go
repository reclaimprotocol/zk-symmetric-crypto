package libraries

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	prover "gnark-symmetric-crypto/libraries/prover/impl"
	verifier "gnark-symmetric-crypto/libraries/verifier/impl"
	"math"
	"math/big"
	"testing"

	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/chacha20"
)

// Initialize test keys and circuits (once)
func init() {
	// Fetch keys and circuits first
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

	// Set up cipher configs with test data
	CipherConfigs["chacha20"].ProverKey = chachaKey
	CipherConfigs["chacha20"].R1CS = chachaR1CS
	CipherConfigs["chacha20-toprf"].ProverKey = chachaOprfKey
	CipherConfigs["chacha20-toprf"].R1CS = chachaOprfr1cs
	CipherConfigs["aes-128-ctr"].ProverKey = aes128Key
	CipherConfigs["aes-128-ctr"].R1CS = aes128r1cs
	CipherConfigs["aes-128-ctr-toprf"].ProverKey = aes128OprfKey
	CipherConfigs["aes-128-ctr-toprf"].R1CS = aes128Oprfr1cs
	CipherConfigs["aes-256-ctr"].ProverKey = aes256Key
	CipherConfigs["aes-256-ctr"].R1CS = aes256r1cs
	CipherConfigs["aes-256-ctr-toprf"].ProverKey = aes256OprfKey
	CipherConfigs["aes-256-ctr-toprf"].R1CS = aes256Oprfr1cs
}

// Simplified test functions using helpers

func TestFullChaCha20_Refactored(t *testing.T) {
	RunFullTest(t, CipherConfigs["chacha20"], false)
}

func TestFullChaCha20OPRF_Refactored(t *testing.T) {
	RunFullTest(t, CipherConfigs["chacha20-toprf"], true) // with boundaries
}

func TestFullAES128_Refactored(t *testing.T) {
	RunFullTest(t, CipherConfigs["aes-128-ctr"], false)
}

func TestFullAES128OPRF_Refactored(t *testing.T) {
	RunFullTest(t, CipherConfigs["aes-128-ctr-toprf"], true) // with boundaries
}

func TestFullAES256_Refactored(t *testing.T) {
	RunFullTest(t, CipherConfigs["aes-256-ctr"], false)
}

func TestFullAES256OPRF_Refactored(t *testing.T) {
	RunFullTest(t, CipherConfigs["aes-256-ctr-toprf"], true) // with boundaries
}

// Additional parameterized tests for different scenarios

func TestAllCiphersWithBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		cipher string
	}{
		{"ChaCha20 OPRF with boundaries", "chacha20-toprf"},
		{"AES128 OPRF with boundaries", "aes-128-ctr-toprf"},
		{"AES256 OPRF with boundaries", "aes-256-ctr-toprf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RunFullTest(t, CipherConfigs[tt.cipher], true)
		})
	}
}

func TestAllCiphersStandard(t *testing.T) {
	tests := []struct {
		name   string
		cipher string
	}{
		{"ChaCha20 standard", "chacha20"},
		{"AES128 standard", "aes-128-ctr"},
		{"AES256 standard", "aes-256-ctr"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RunFullTest(t, CipherConfigs[tt.cipher], false)
		})
	}
}

// Benchmark functions using helpers

func BenchmarkProveChaCha20(b *testing.B) {
	RunBenchmark(b, CipherConfigs["chacha20"])
}

func BenchmarkProveAES128(b *testing.B) {
	RunBenchmark(b, CipherConfigs["aes-128-ctr"])
}

func BenchmarkProveAES256(b *testing.B) {
	RunBenchmark(b, CipherConfigs["aes-256-ctr"])
}

// Parameterized benchmarks for all ciphers

func BenchmarkProveAllStandardCiphers(b *testing.B) {
	benchmarks := []struct {
		name   string
		cipher string
	}{
		{"ChaCha20", "chacha20"},
		{"AES128", "aes-128-ctr"},
		{"AES256", "aes-256-ctr"},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			RunBenchmark(b, CipherConfigs[bm.cipher])
		})
	}
}

// TestChaCha20OPRFWithZeroBoundary tests the case where second block has zero boundary
func TestChaCha20OPRFWithZeroBoundary(t *testing.T) {
	// Scenario: Only 12 bytes need OPRF processing
	// Block 0: 12 bytes (contains the OPRF data)
	// Block 1: 0 bytes (exists in circuit but contributes nothing)

	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs))

	bKey := make([]byte, 32)
	rand.Read(bKey)

	// Create 12 bytes of plaintext
	plaintext := make([]byte, 12)
	email := "test@em.com" // 11 bytes
	emailBytes := []byte(email)
	copy(plaintext[0:], emailBytes)
	plaintext[11] = 0x42 // Some data after email

	// Encrypt only the first 12 bytes
	bNonce1 := make([]byte, 12)
	rand.Read(bNonce1)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter1 := uint32(tmp.Uint64())

	ciphertext := make([]byte, 12)
	// Use ChaCha20 to encrypt
	cipher, _ := chacha20.NewUnauthenticatedCipher(bKey, bNonce1)
	cipher.SetCounter(counter1)
	cipher.XORKeyStream(ciphertext, plaintext)

	// TOPRF setup
	domainSeparator := "reclaim"
	oprfData := GenerateOPRFData(t, emailBytes)

	// Create blocks - second block has zero boundary
	zero := uint32(0)
	twelve := uint32(12)
	blocks := []prover.Block{
		{
			Nonce:    bNonce1,
			Counter:  counter1,
			Boundary: &twelve, // First block has 12 bytes
		},
		{
			Nonce:    make([]byte, 12), // Dummy nonce for empty block
			Counter:  0,
			Boundary: &zero, // Second block has 0 bytes (empty)
		},
	}

	inputParams := &prover.InputParams{
		Cipher: "chacha20-toprf",
		Key:    bKey,
		Blocks: blocks,
		Input:  ciphertext, // Only 12 bytes
		TOPRF: &prover.TOPRFParams{
			Pos:             0,
			Len:             uint32(len(emailBytes)),
			Mask:            oprfData.Mask,
			DomainSeparator: []byte(domainSeparator),
			Output:          oprfData.Output,
			Responses:       oprfData.Responses,
		},
	}

	buf, _ := json.Marshal(inputParams)

	fmt.Println(string(buf))
	res := prover.Prove(buf)
	assert.True(len(res) > 0)

	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	// Create verifier blocks
	verifierBlocks := []verifier.Block{
		{
			Nonce:    bNonce1,
			Counter:  counter1,
			Boundary: &twelve,
		},
		{
			Nonce:    make([]byte, 12),
			Counter:  0,
			Boundary: &zero,
		},
	}

	// Create verification params
	verifyResponses := make([]*verifier.TOPRFResponse, len(oprfData.Responses))
	for i, r := range oprfData.Responses {
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
		Input:  ciphertext,
		TOPRF: &verifier.TOPRFParams{
			Pos:             0,
			Len:             uint32(len(emailBytes)),
			DomainSeparator: []byte(domainSeparator),
			Output:          oprfData.Output,
			Responses:       verifyResponses,
		},
	}

	publicSignals, _ := json.Marshal(oprfParams)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignals,
	}

	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

// TestAES128OPRFWithMixedBoundaries tests AES with mixed boundaries including zero blocks
func TestAES128OPRFWithMixedBoundaries(t *testing.T) {
	// Scenario: 42 bytes total (16 + 16 + 10 + 0 + 0)
	// Block 0: 16 bytes (full)
	// Block 1: 16 bytes (full)
	// Block 2: 10 bytes (partial)
	// Block 3: 0 bytes (empty)
	// Block 4: 0 bytes (empty)

	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs))

	bKey := make([]byte, 16)
	rand.Read(bKey)

	// Create 42 bytes of plaintext
	plaintext := make([]byte, 42)
	rand.Read(plaintext)

	// Place email at position 20 (middle of block 1 into block 2)
	email := "test@email.com" // 14 bytes
	emailBytes := []byte(email)
	copy(plaintext[20:], emailBytes)

	// Generate unique nonces and counters for each block
	nonces := make([][]byte, 5)
	counters := make([]uint32, 5)
	for i := 0; i < 5; i++ {
		nonces[i] = make([]byte, 12)
		rand.Read(nonces[i])
		tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
		counters[i] = uint32(tmp.Uint64())
	}

	// Encrypt the data based on boundaries
	ciphertext := make([]byte, 42)

	// Block 0: Full 16 bytes
	encryptAESBlock(bKey, nonces[0], counters[0], plaintext[0:16], ciphertext[0:16])

	// Block 1: Full 16 bytes
	encryptAESBlock(bKey, nonces[1], counters[1], plaintext[16:32], ciphertext[16:32])

	// Block 2: Only 10 bytes
	encryptAESBlock(bKey, nonces[2], counters[2], plaintext[32:42], ciphertext[32:42])

	// Blocks 3 and 4: Empty (0 bytes) - no encryption needed

	// TOPRF setup
	domainSeparator := "reclaim"
	oprfData := GenerateOPRFData(t, emailBytes)

	// Create blocks with mixed boundaries
	zero := uint32(0)
	ten := uint32(10)
	blocks := []prover.Block{
		{
			Nonce:   nonces[0],
			Counter: counters[0],
			// No boundary means full block (16 bytes)
		},
		{
			Nonce:   nonces[1],
			Counter: counters[1],
			// No boundary means full block (16 bytes)
		},
		{
			Nonce:    nonces[2],
			Counter:  counters[2],
			Boundary: &ten, // 10 bytes
		},
		{
			Nonce:    nonces[3],
			Counter:  counters[3],
			Boundary: &zero, // 0 bytes (empty)
		},
		{
			Nonce:    nonces[4],
			Counter:  counters[4],
			Boundary: &zero, // 0 bytes (empty)
		},
	}

	inputParams := &prover.InputParams{
		Cipher: "aes-128-ctr-toprf",
		Key:    bKey,
		Blocks: blocks,
		Input:  ciphertext, // 42 bytes
		TOPRF: &prover.TOPRFParams{
			Pos:             20, // Email starts at position 20
			Len:             uint32(len(emailBytes)),
			Mask:            oprfData.Mask,
			DomainSeparator: []byte(domainSeparator),
			Output:          oprfData.Output,
			Responses:       oprfData.Responses,
		},
	}

	buf, _ := json.Marshal(inputParams)
	fmt.Println("AES mixed boundaries test:")
	fmt.Println(string(buf))

	res := prover.Prove(buf)
	assert.True(len(res) > 0)

	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	// Create verifier blocks
	verifierBlocks := []verifier.Block{
		{
			Nonce:   nonces[0],
			Counter: counters[0],
			// nil boundary = full block
		},
		{
			Nonce:   nonces[1],
			Counter: counters[1],
			// nil boundary = full block
		},
		{
			Nonce:    nonces[2],
			Counter:  counters[2],
			Boundary: &ten,
		},
		{
			Nonce:    nonces[3],
			Counter:  counters[3],
			Boundary: &zero,
		},
		{
			Nonce:    nonces[4],
			Counter:  counters[4],
			Boundary: &zero,
		},
	}

	// Create verification params
	verifyResponses := make([]*verifier.TOPRFResponse, len(oprfData.Responses))
	for i, r := range oprfData.Responses {
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
		Input:  ciphertext,
		TOPRF: &verifier.TOPRFParams{
			Pos:             20,
			Len:             uint32(len(emailBytes)),
			DomainSeparator: []byte(domainSeparator),
			Output:          oprfData.Output,
			Responses:       verifyResponses,
		},
	}

	publicSignals, _ := json.Marshal(oprfParams)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof,
		PublicSignals: publicSignals,
	}

	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

// Helper function to encrypt AES block
func encryptAESBlock(key []byte, nonce []byte, counter uint32, plaintext, ciphertext []byte) {
	block, _ := aes.NewCipher(key)
	ctr := cipher.NewCTR(block, append(nonce, binary.BigEndian.AppendUint32(nil, counter)...))
	ctr.XORKeyStream(ciphertext, plaintext)
}
