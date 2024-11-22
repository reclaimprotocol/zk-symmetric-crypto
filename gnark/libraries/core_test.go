package libraries

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	"gnark-symmetric-crypto/circuits/toprf"
	prover "gnark-symmetric-crypto/libraries/prover/impl"
	verifier "gnark-symmetric-crypto/libraries/verifier/impl"
	"gnark-symmetric-crypto/libraries/verifier/oprf"
	"gnark-symmetric-crypto/utils"
	"math"
	"math/big"
	"os"
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
	assert.True(prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS))
	assert.True(prover.InitAlgorithm(prover.AES_128, aes128Key, aes128r1cs))
	assert.True(prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs))
	assert.True(prover.InitAlgorithm(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs))
	assert.True(prover.InitAlgorithm(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs))
	assert.True(prover.InitAlgorithm(prover.AES_256_OPRF, aes256OprfKey, aes256Oprfr1cs))
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
	bPt := make([]byte, aes_v2.BLOCKS*16)
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
	bPt := make([]byte, aes_v2.BLOCKS*16)
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

	emailBytes := []byte(email)

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
			Index:          r.Index,
			PublicKeyShare: r.PublicKeyShare,
			Evaluated:      r.Evaluated,
			C:              r.C,
			R:              r.R,
		}
	}
	oprfParams := &verifier.InputTOPRFParams{
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

func TestFullAES128OPRF(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs))
	bKey := make([]byte, 16)
	bNonce := make([]byte, 12)
	bOutput := make([]byte, aes_v2.BLOCKS*16) // circuit output is plaintext
	bInput := make([]byte, aes_v2.BLOCKS*16)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bOutput)

	email := "test@email.com"
	domainSeparator := "reclaim"

	emailBytes := []byte(email)

	pos := uint32(12)
	copy(bOutput[pos:], email)

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
	ctr := cipher.NewCTR(block, append(bNonce, binary.BigEndian.AppendUint32(nil, counter)...))
	ctr.XORKeyStream(bInput, bOutput)

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

	inputParams := &prover.InputParams{
		Cipher:  "aes-128-ctr-toprf",
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
			Index:          r.Index,
			PublicKeyShare: r.PublicKeyShare,
			Evaluated:      r.Evaluated,
			C:              r.C,
			R:              r.R,
		}
	}
	oprfParams := &verifier.InputTOPRFParams{
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
func TestFullAES256OPRF(t *testing.T) {
	assert := test.NewAssert(t)
	assert.True(prover.InitAlgorithm(prover.AES_256_OPRF, aes256OprfKey, aes256Oprfr1cs))
	bKey := make([]byte, 32)
	bNonce := make([]byte, 12)
	bOutput := make([]byte, aes_v2.BLOCKS*16) // circuit output is plaintext
	bInput := make([]byte, aes_v2.BLOCKS*16)
	tmp, _ := rand.Int(rand.Reader, big.NewInt(math.MaxUint32))
	counter := uint32(tmp.Uint64())

	rand.Read(bKey)
	rand.Read(bNonce)
	rand.Read(bOutput)

	email := "test@email.com"
	domainSeparator := "reclaim"

	emailBytes := []byte(email)

	pos := uint32(12)
	copy(bOutput[pos:], email)

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}
	ctr := cipher.NewCTR(block, append(bNonce, binary.BigEndian.AppendUint32(nil, counter)...))
	ctr.XORKeyStream(bInput, bOutput)

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

	inputParams := &prover.InputParams{
		Cipher:  "aes-256-ctr-toprf",
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
			Index:          r.Index,
			PublicKeyShare: r.PublicKeyShare,
			Evaluated:      r.Evaluated,
			C:              r.C,
			R:              r.R,
		}
	}
	oprfParams := &verifier.InputTOPRFParams{
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
	params := `{"cipher":"aes-128-ctr","key":"Ilqk8vMs/lrdrt9bEpM3qQ==","nonce":"/T8j2un1mcMh0Lt4","counter":298071680,"input":"mBiZrxJnp1ALlddPWenBt12YsVzSMFudhjbMC9rZtx//D0LMi5R8+/bzkKZgTaoxy3N0Gdgf5//U7kObAKBNE3votSHtiNhZUUZsoUvD5fw="}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveAES256(b *testing.B) {
	prover.InitAlgorithm(prover.AES_256, aes256Key, aes256r1cs)
	b.ResetTimer()
	params := `{"cipher":"aes-256-ctr","key":"D90Byc5KBESfgf52T5T+VbKIR56UCldsfD/k3QRq1FU=","nonce":"xaPdohzb+eNGkzhl","counter":2841725616,"input":"l4nng90p9WsrHCVYqIB0UoBPEOnZxigJ7qSGTRMU5nEgrXO7CpqmQov0p4eZ4bKJI3SvpgQ2jxqu+FJDjzINA9aI72YcXf4AYGtI8+sl/Ig="}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveChacha(b *testing.B) {
	prover.InitAlgorithm(prover.CHACHA20, chachaKey, chachaR1CS)
	b.ResetTimer()
	params := `{"cipher":"chacha20","key":"DAKfm7e+mFt0cCGacGmnDm5fVZ7UWyv7O53J27yePbs=","nonce":"I3zQZE9P8e7lXG6a","counter":1757507854,"input":"ShLAJduinXP+uOyxYoFNcUzR4c59QbcFed8YlIBPD3yRJhrVwB06tAIfP0TC2AUMztD7q60vAsK/at+WI9U0+fsgNDLhqI912HvyE1oUFm5XHpTC5VtVg1p0N4/ZjXaa7Wd9sWc2ty5eP8lEjGVzyRX6Goi+vygtkwh/1qJRc/I="}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveAES128OPRF(b *testing.B) {
	prover.InitAlgorithm(prover.AES_128_OPRF, aes128OprfKey, aes128Oprfr1cs)
	b.ResetTimer()
	params := `{"cipher":"aes-128-ctr-toprf","key":"ZAWxNb2AdgO39yzI14XsZA==","nonce":"LBsTWdRfQ2J7unF2","counter":2260824246,"input":"UTnKUAkCBrEYiC2tPMnGliYTdcbVFXrFhFRH3m3N5zl5XUhfljrNTdquVVeL2PleSc3w5m2ZI6kVePRaC/OWC8tQjwk4n7WpB8D4IpqQHSU=","toprf":{"pos":12,"len":14,"mask":"A1BXFdPv8/KMIWHKi5ayD+Ngj2x8CEqPIXaS94kBNxg=","domainSeparator":"cmVjbGFpbQ==","output":"IShCRuW+UON6xy/va104/4qxauCxbF/boK4SjbExTMM=","responses":[{"index":0,"publicKeyShare":"n/wRU9Jw6bMF/f+IwhF3SJmBQ9IevOCcNu6HOGV7NQg=","evaluated":"KhzfVQOJZfu7tacCPV82IzgmZsl9m4g931kTPvmg16Q=","c":"LeUBWWxMeLTK201i0QcyFEguuBwHOIkgWyebJHb4KuY=","r":"ATMhm3RUePybiYqj+dGM8OssXZPpkGXVeiNdoxKHhLY="}]}}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveAES256OPRF(b *testing.B) {
	prover.InitAlgorithm(prover.AES_256_OPRF, aes256OprfKey, aes256Oprfr1cs)
	b.ResetTimer()
	params := `{"cipher":"aes-256-ctr-toprf","key":"4IpME0BPXBIlVL7TdbRPktZVqqxQ+cUZaZN1ZQH+HXI=","nonce":"mMrCGydl9N4uwKxN","counter":4148389242,"input":"6DOHCarJBb8OdKf3cWakFKgn9BV/eVPQPaBlNwSRHA7GoGs6ijTygZwuBsYGbIw35q3U+OHyhD5M181U7Mx25uaFlZzbMr6xPp0LYk4YWuM=","toprf":{"pos":12,"len":14,"mask":"jiWalfzXdcn7geSk8UmfvaIzHiBo9AlhIm4mJT6qhg==","domainSeparator":"cmVjbGFpbQ==","output":"L0io3LqaeEdNSnZBJzAM46zlxZH30wxNf38cEvYWhhw=","responses":[{"index":1,"publicKeyShare":"y1wKCxI/i+OF8Nfjc9DyXmz67DtfWxk9fWnlFqTnlxs=","evaluated":"UApaFttzi54ShGcrXcpMKapa4emphZbdI3MNsKBjMpw=","c":"GWQKZ7Q54L2TjDvLtywRuD6AXt+8uvrQ+jGHuKIIpY4=","r":"A4RxrU5gOa0LMgLKhHVp4SfknOvYIIOLcWVPBwJ7zj4="}]}}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func Benchmark_ProveChachaOPRF(b *testing.B) {
	prover.InitAlgorithm(prover.CHACHA20_OPRF, chachaOprfKey, chachaOprfr1cs)
	b.ResetTimer()
	params := `{"cipher":"chacha20-toprf","key":"Ka3Qs7LgwGaRQwIXYSQKYF1bpKX7BntH1+gbgiMHyYM=","nonce":"yLApW3mIK0mM3uE9","counter":4168221410,"input":"zDdyXezLpcexVGYoZoyuFIDjpXZCV+YSVbDd5SfRHge7HEril7C0gnqR7dPbMwj/2t9g5mU4x/2bvl+grkeyUT33HCyRvebvAEfDkGENP5aO2MC71P7ynYGIAV7/4QbkflQRA9pdKOHfqCSEzd4GqNaaIKzF1/A6AHXuaeOOg5U=","toprf":{"pos":59,"len":14,"mask":"BIvVtZdOIiZSDWb1/sLKqoEXhx4mc4Kmv580KPbll3Q=","domainSeparator":"cmVjbGFpbQ==","output":"CUcueErhemKezndgP7vjGImvG8ua9104RJe8QhNcuOc=","responses":[{"index":0,"publicKeyShare":"0W07hZxwL42VhLULWKIkYDAuukzGBuCafqZVPTWPrq8=","evaluated":"JxObYdh6IlUR4+GV6Z1oBcWr5wEnWzuWUHX07gGQ+So=","c":"FUBwJawrBPQe3OJs6zLj4vpz2SEG4AU1Q6ucXIZrCyM=","r":"A8NG/ewWaCAef6Mowvq4XTgVtRRcRvaD6edkrsirUOw="}]}}`
	for i := 0; i < b.N; i++ {
		prover.Prove([]byte(params))
	}
	b.ReportAllocs()
}

func fetchFile(keyName string) ([]byte, error) {
	f, err := os.ReadFile("../../resources/gnark/" + keyName)
	if err != nil {
		panic(err)
	}
	return f, nil
}
