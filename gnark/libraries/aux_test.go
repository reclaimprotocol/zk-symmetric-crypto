package libraries

import (
	"crypto/rand"
	"encoding/json"
	aes_v2 "github.com/reclaimprotocol/zk-symmetric-crypto/gnark/circuits/aesV2"
	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/circuits/chachaV3"
	prover "github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/impl"
	oprf2 "github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/oprf"
	verifier "github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/verifier/impl"
	"math"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/consensys/gnark/test"
)

var chachaKey, aes128Key, aes256Key, chachaOprfKey, aes128OprfKey, aes256OprfKey,
	chachaR1CS, aes128r1cs, aes256r1cs, chachaOprfr1cs, aes128Oprfr1cs, aes256Oprfr1cs []byte

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
	bIn := make([]byte, 64*chachaV3.Blocks)

	rand.Read(bKey)
	rand.Read(bIn)

	// Create truly random nonces and counters for each block
	blocks := make([]prover.Block, chachaV3.Blocks)
	for b := 0; b < chachaV3.Blocks; b++ {
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
