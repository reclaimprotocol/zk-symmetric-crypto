package libraries

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"gnark-symmetric-crypto/circuits/toprf"
	prover "gnark-symmetric-crypto/libraries/prover/impl"
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

var chachaKey, aes128Key, aes256Key, chachaOprfKey, chachaR1CS, aes128r1cs, aes256r1cs, chachaOprfr1cs []byte

func init() {
	chachaKey, _ = fetchFile("pk.chacha20")
	aes128Key, _ = fetchFile("pk.aes128")
	aes256Key, _ = fetchFile("pk.aes256")
	chachaOprfKey, _ = fetchFile("pk.chacha20_oprf")

	chachaR1CS, _ = fetchFile("r1cs.chacha20")
	aes128r1cs, _ = fetchFile("r1cs.aes128")
	aes256r1cs, _ = fetchFile("r1cs.aes256")
	chachaOprfr1cs, _ = fetchFile("r1cs.chacha20_oprf")
}

func TestInit(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS))
	assert.True(prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs))
	assert.True(prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs))
	//	assert.True(prover.InitAlgorithm(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs))

}

func TestProveVerify(t *testing.T) {
	assert := test.NewAssert(t)

	proofs := make([][]byte, 0, 3)

	wg := new(sync.WaitGroup)
	wg.Add(3)
	go func() {
		assert.True(prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS))
		params := `{"cipher":"chacha20","key":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"nonce":[3,3,3,3,3,3,3,3,3,3,3,3],"counter":3,"input":[163,247,229,146,174,218,21,7,167,245,27,53,129,45,252,80,162,99,213,166,210,223,98,94,86,59,2,228,156,8,191,48,208,231,72,63,91,19,255,7,149,50,34,78,232,251,195,26,177,137,155,24,228,83,211,109,151,147,168,53,94,176,222,233]}`
		res := prover.Prove([]byte(params))
		assert.NotNil(res)
		var outParams *prover.OutputParams
		json.Unmarshal(res, &outParams)

		var inParams *prover.InputParams
		json.Unmarshal([]byte(params), &inParams)

		signals := outParams.PublicSignals
		signals = append(signals, inParams.Nonce...)
		bCounter := make([]byte, 4)
		binary.LittleEndian.PutUint32(bCounter, inParams.Counter)
		signals = append(signals, bCounter...)
		signals = append(signals, inParams.Input...)

		inParams2 := &verifier.InputVerifyParams{
			Cipher:        "chacha20",
			Proof:         outParams.Proof.ProofJson,
			PublicSignals: signals,
		}
		inBuf, _ := json.Marshal(inParams2)
		proofs = append(proofs, inBuf)
		wg.Done()
	}()

	go func() {
		assert.True(prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs))
		params := `{"cipher":"aes-128-ctr","key":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"nonce":[3,3,3,3,3,3,3,3,3,3,3,3],"counter":2,"input":[183,4,206,60,254,21,117,9,150,227,246,245,71,101,56,67,79,93,44,163,22,89,128,55,214,254,228,214,89,253,176,112,138,115,93,140,194,222,104,252,49,144,91,252,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
		res := prover.Prove([]byte(params))
		assert.NotNil(res)

		var outParams *prover.OutputParams
		json.Unmarshal(res, &outParams)

		var inParams *prover.InputParams
		json.Unmarshal([]byte(params), &inParams)

		signals := outParams.PublicSignals
		signals = append(signals, inParams.Nonce...)
		bCounter := make([]byte, 4)
		binary.BigEndian.PutUint32(bCounter, inParams.Counter)
		signals = append(signals, bCounter...)
		signals = append(signals, inParams.Input...)

		inParams2 := &verifier.InputVerifyParams{
			Cipher:        "aes-128-ctr",
			Proof:         outParams.Proof.ProofJson,
			PublicSignals: signals,
		}
		inBuf, _ := json.Marshal(inParams2)
		proofs = append(proofs, inBuf)
		wg.Done()
	}()

	go func() {
		assert.True(prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs))
		params := `{"cipher":"aes-256-ctr","key":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"nonce":[3,3,3,3,3,3,3,3,3,3,3,3],"counter":10,"input":[189,250,225,242,6,46,173,203,7,166,62,139,67,150,1,155,64,122,211,198,184,203,124,194,99,34,127,29,236,17,232,214,154,146,78,217,254,224,208,196,55,200,23,93,90,175,240,31,31,225,26,15,219,156,123,21,103,98,205,87,197,22,245,158]}`
		res := prover.Prove([]byte(params))
		assert.NotNil(res)

		var outParams *prover.OutputParams
		json.Unmarshal(res, &outParams)

		var inParams *prover.InputParams
		json.Unmarshal([]byte(params), &inParams)
		signals := outParams.PublicSignals
		signals = append(signals, inParams.Nonce...)
		bCounter := make([]byte, 4)
		binary.BigEndian.PutUint32(bCounter, inParams.Counter)
		signals = append(signals, bCounter...)
		signals = append(signals, inParams.Input...)

		inParams2 := &verifier.InputVerifyParams{
			Cipher:        "aes-256-ctr",
			Proof:         outParams.Proof.ProofJson,
			PublicSignals: signals,
		}
		inBuf, _ := json.Marshal(inParams2)
		proofs = append(proofs, inBuf)
		wg.Done()
	}()

	wg.Wait()

	assert.Equal(3, len(proofs))

	for _, proof := range proofs {
		assert.True(verifier.Verify(proof))
	}
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
	bIn := make([]byte, 64)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bIn)

	inputParams := &prover.InputParams{
		Cipher:  "chacha20",
		Key:     bKey,
		Nonce:   bNonce,
		Counter: counter,
		Input:   bIn,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	signals := outParams.PublicSignals
	signals = append(signals, bNonce...)
	bCounter := make([]byte, 4)
	binary.LittleEndian.PutUint32(bCounter, counter)
	signals = append(signals, bCounter...)
	signals = append(signals, bIn...)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof.ProofJson,
		PublicSignals: signals,
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
	bPt := make([]byte, 64)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bPt)

	inputParams := &prover.InputParams{
		Cipher:  "aes-256-ctr",
		Key:     bKey,
		Nonce:   bNonce,
		Counter: counter,
		Input:   bPt,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	signals := outParams.PublicSignals
	signals = append(signals, bNonce...)
	bCounter := make([]byte, 4)
	binary.BigEndian.PutUint32(bCounter, counter)
	signals = append(signals, bCounter...)
	signals = append(signals, bPt...)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof.ProofJson,
		PublicSignals: signals,
	}
	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

func TestFullAES128(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs))
	bKey := make([]byte, 16)
	bNonce := make([]byte, 12)
	bPt := make([]byte, 64)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bPt)

	inputParams := &prover.InputParams{
		Cipher:  "aes-128-ctr",
		Key:     bKey,
		Nonce:   bNonce,
		Counter: counter,
		Input:   bPt,
	}

	buf, _ := json.Marshal(inputParams)

	res := prover.Prove(buf)
	assert.True(len(res) > 0)
	var outParams *prover.OutputParams
	json.Unmarshal(res, &outParams)

	signals := outParams.PublicSignals
	signals = append(signals, bNonce...)
	bCounter := make([]byte, 4)
	binary.BigEndian.PutUint32(bCounter, counter)
	signals = append(signals, bCounter...)
	signals = append(signals, bPt...)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof.ProofJson,
		PublicSignals: signals,
	}
	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

func TestFullChaCha20OPRF(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs))
	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)
	bOutput := make([]byte, 128) // circuit output is plaintext
	bInput := make([]byte, 128)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bOutput)

	email := "test@email.com"
	domainSeparator := "reclaim"
	pos := uint32(59)
	copy(bOutput[pos:], email)

	cipher, err := chacha20.NewUnauthenticatedCipher(bKey, bNonce)
	assert.NoError(err)

	cipher.SetCounter(counter)
	cipher.XORKeyStream(bInput, bOutput)

	// TOPRF setup

	threshold := toprf.Threshold
	nodes := threshold + 1

	tParams := &oprf.InputGenerateParams{
		Nodes:     uint8(nodes),
		Threshold: uint8(threshold),
	}

	btParams, err := json.Marshal(tParams)
	assert.NoError(err)

	bShares := oprf.TOPRFGenerateSharedKey(btParams)

	var shares *oprf.OutputGenerateParams
	err = json.Unmarshal(bShares, &shares)
	assert.NoError(err)

	req, err := utils.OPRFGenerateRequest(email, domainSeparator)
	assert.NoError(err)

	// TOPRF requests
	idxs := utils.PickRandomIndexes(nodes, threshold)

	responses := make([]*prover.TOPRFResponse, threshold)

	for i := 0; i < threshold; i++ {
		sk := new(big.Int).SetBytes(shares.Shares[idxs[i]].PrivateKey)
		evalResult, err := utils.OPRFEvaluate(sk, req.MaskedData)
		assert.NoError(err)

		resp := &prover.TOPRFResponse{
			Index:     uint8(idxs[i]),
			PublicKey: shares.Shares[idxs[i]].PublicKey,
			Evaluated: evalResult.EvaluatedPoint.Marshal(),
			C:         evalResult.C.Bytes(),
			R:         evalResult.R.Bytes(),
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

	inputParams := &prover.InputParams{
		Cipher:  "chacha20-toprf",
		Key:     bKey,
		Nonce:   bNonce,
		Counter: counter,
		Input:   bInput,
		TOPRF: &prover.TOPRFParams{
			Pos:             pos,
			Len:             uint32(len([]byte(email))),
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
	assert.NoError(err)

	verifyResponses := make([]*verifier.TOPRFResponse, threshold)
	for i := 0; i < threshold; i++ {
		r := responses[i]
		verifyResponses[i] = &verifier.TOPRFResponse{
			Index:     r.Index,
			PublicKey: r.PublicKey,
			Evaluated: r.Evaluated,
			C:         r.C,
			R:         r.R,
		}
	}
	oprfParams := &verifier.InputChachaTOPRFParams{
		Nonce:   bNonce,
		Counter: counter,
		Input:   bInput,
		TOPRF: &verifier.TOPRFParams{
			Pos:             pos,
			Len:             uint32(len([]byte(email))),
			DomainSeparator: []byte(domainSeparator),
			Output:          out.Bytes(),
			Responses:       verifyResponses,
		},
	}

	publicSignals, err := json.Marshal(oprfParams)
	assert.NoError(err)

	inParams := &verifier.InputVerifyParams{
		Cipher:        inputParams.Cipher,
		Proof:         outParams.Proof.ProofJson,
		PublicSignals: publicSignals,
	}
	inBuf, _ := json.Marshal(inParams)
	assert.True(verifier.Verify(inBuf))
}

func Benchmark_ProveAES128(b *testing.B) {
	prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs)
	b.ResetTimer()
	params := `{"cipher":"aes-128-ctr","key":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"nonce":[3,3,3,3,3,3,3,3,3,3,3,3],"counter":2,"input":[183,4,206,60,254,21,117,9,150,227,246,245,71,101,56,67,79,93,44,163,22,89,128,55,214,254,228,214,89,253,176,112,138,115,93,140,194,222,104,252,49,144,91,252,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveAES256(b *testing.B) {
	prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs)
	b.ResetTimer()
	params := `{"cipher":"aes-256-ctr","key":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"nonce":[3,3,3,3,3,3,3,3,3,3,3,3],"counter":10,"input":[189,250,225,242,6,46,173,203,7,166,62,139,67,150,1,155,64,122,211,198,184,203,124,194,99,34,127,29,236,17,232,214,154,146,78,217,254,224,208,196,55,200,23,93,90,175,240,31,31,225,26,15,219,156,123,21,103,98,205,87,197,22,245,158]}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveChacha(b *testing.B) {
	prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS)
	b.ResetTimer()
	params := `{"cipher":"chacha20","key":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"nonce":[3,3,3,3,3,3,3,3,3,3,3,3],"counter":3,"input":[163,247,229,146,174,218,21,7,167,245,27,53,129,45,252,80,162,99,213,166,210,223,98,94,86,59,2,228,156,8,191,48,208,231,72,63,91,19,255,7,149,50,34,78,232,251,195,26,177,137,155,24,228,83,211,109,151,147,168,53,94,176,222,233]}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func fetchFile(keyName string) ([]byte, error) {
	f, err := os.ReadFile("../circuits/generated/" + keyName)
	if err != nil {
		panic(err)
	}
	return f, nil
}
