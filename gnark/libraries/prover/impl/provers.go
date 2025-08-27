package impl

import "C"
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	aes_v2_oprf "gnark-symmetric-crypto/circuits/aesV2_oprf"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/circuits/chachaV3_oprf"
	"gnark-symmetric-crypto/circuits/toprf"
	"gnark-symmetric-crypto/utils"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"golang.org/x/crypto/chacha20"
)

func init() {
	// std.RegisterHints()
}

type TOPRFResponse struct {
	Index          uint8   `json:"index"`
	PublicKeyShare []byte  `json:"publicKeyShare"`
	Evaluated      []uint8 `json:"evaluated"`
	C              []byte  `json:"c"`
	R              []byte  `json:"r"`
}

type Location struct {
	Pos uint32 `json:"pos"`
	Len uint32 `json:"len"`
}

type TOPRFParams struct {
	Locations       []Location       `json:"locations"`
	Mask            []uint8          `json:"mask"`
	DomainSeparator []uint8          `json:"domainSeparator"`
	Output          []uint8          `json:"output"`
	Responses       []*TOPRFResponse `json:"responses"`
}

type Block struct {
	Nonce    []uint8 `json:"nonce"`              // 12 bytes for both AES and ChaCha
	Counter  uint32  `json:"counter"`            // Block counter
	Boundary *uint32 `json:"boundary,omitempty"` // Optional: actual data bytes in this block (nil=full, 0=empty)
}

type InputParams struct {
	Cipher string       `json:"cipher"`
	Key    []uint8      `json:"key"`
	Blocks []Block      `json:"blocks"` // Array of blocks with nonce, counter, and optional boundary
	Input  []uint8      `json:"input"`  // usually it's redacted ciphertext
	TOPRF  *TOPRFParams `json:"toprf,omitempty"`
}

// Helper functions to extract arrays for backward compatibility
func (ip *InputParams) GetNonces() [][]uint8 {
	nonces := make([][]uint8, len(ip.Blocks))
	for i, block := range ip.Blocks {
		nonces[i] = block.Nonce
	}
	return nonces
}

func (ip *InputParams) GetCounters() []uint32 {
	counters := make([]uint32, len(ip.Blocks))
	for i, block := range ip.Blocks {
		counters[i] = block.Counter
	}
	return counters
}

func (ip *InputParams) GetBoundaries() []uint32 {
	boundaries := make([]uint32, len(ip.Blocks))
	for i, block := range ip.Blocks {
		if block.Boundary != nil {
			// Use the explicit boundary value (could be 0 for empty block)
			boundaries[i] = *block.Boundary
		} else {
			// nil means use default full block size
			switch ip.Cipher {
			case "chacha20", "chacha20-toprf":
				boundaries[i] = 64 // ChaCha20 block size
			case "aes-128-ctr", "aes-256-ctr", "aes-128-ctr-toprf", "aes-256-ctr-toprf":
				boundaries[i] = 16 // AES block size
			}
		}
	}
	return boundaries
}

type Prover interface {
	SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey)
	Prove(params *InputParams) (proof []byte, output []uint8)
}

type baseProver struct {
	r1cs constraint.ConstraintSystem
	pk   groth16.ProvingKey
}

type ChaChaProver struct {
	baseProver
}

func (cp *ChaChaProver) SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey) {
	cp.r1cs = r1cs
	cp.pk = pk
}
func (cp *ChaChaProver) Prove(params *InputParams) (proof []byte, output []uint8) {

	key, nonces, counters, input := params.Key, params.GetNonces(), params.GetCounters(), params.Input

	if len(key) != 32 {
		log.Panicf("key length must be 32: %d", len(key))
	}
	if len(params.Blocks) != chachaV3.Blocks {
		log.Panicf("blocks array length must be %d: %d", chachaV3.Blocks, len(params.Blocks))
	}
	for i, block := range params.Blocks {
		if len(block.Nonce) != 12 {
			log.Panicf("block[%d] nonce length must be 12: %d", i, len(block.Nonce))
		}
	}
	if len(input) != 64*chachaV3.Blocks {
		log.Panicf("input length must be %d: %d", 64*chachaV3.Blocks, len(input))
	}

	// calculate output ourselves for each block
	output = make([]byte, len(input))
	blockSize := 64 // ChaCha20 has 64-byte blocks

	for b := 0; b < chachaV3.Blocks; b++ {
		start := b * blockSize
		end := start + blockSize

		ctr, err := chacha20.NewUnauthenticatedCipher(key, nonces[b])
		if err != nil {
			panic(err)
		}

		ctr.SetCounter(counters[b])
		ctr.XORKeyStream(output[start:end], input[start:end])
	}

	// convert input values to bits preserving byte order

	// plaintext & ciphertext are in BE order
	bInput := utils.BytesToUint32BEBits(input)
	bOutput := utils.BytesToUint32BEBits(output)

	// everything else in LE order
	bKey := utils.BytesToUint32LEBits(key)

	witness := &chachaV3.ChaChaCircuit{}

	copy(witness.Key[:], bKey)

	// Set per-block nonce and counter from arrays
	for b := 0; b < chachaV3.Blocks; b++ {
		bNonce := utils.BytesToUint32LEBits(nonces[b])
		copy(witness.Nonce[b][:], bNonce)
		witness.Counter[b] = utils.Uint32ToBits(counters[b])
	}

	copy(witness.In[:], bInput)
	copy(witness.Out[:], bOutput)

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	gProof, err := groth16.Prove(cp.r1cs, cp.pk, wtns)
	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	_, err = gProof.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	return buf.Bytes(), output
}

type AESProver struct {
	baseProver
}

func (ap *AESProver) SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey) {
	ap.r1cs = r1cs
	ap.pk = pk
}
func (ap *AESProver) Prove(params *InputParams) (proof []byte, output []uint8) {

	key, nonces, counters, input := params.Key, params.GetNonces(), params.GetCounters(), params.Input

	if len(key) != 32 && len(key) != 16 {
		log.Panicf("key length must be 16 or 32: %d", len(key))
	}
	if len(params.Blocks) != aes_v2.BLOCKS {
		log.Panicf("blocks array length must be %d: %d", aes_v2.BLOCKS, len(params.Blocks))
	}
	for i, block := range params.Blocks {
		if len(block.Nonce) != 12 {
			log.Panicf("block[%d] nonce length must be 12: %d", i, len(block.Nonce))
		}
	}
	if len(input) != aes_v2.BLOCKS*16 {
		log.Panicf("input length must be %d: %d", aes_v2.BLOCKS*16, len(input))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	output = make([]byte, len(input))
	blockSize := 16 // AES has 16-byte blocks

	// Process each block with its own nonce and counter
	for b := 0; b < aes_v2.BLOCKS; b++ {
		start := b * blockSize
		end := start + blockSize
		if end > len(input) {
			end = len(input)
		}

		// Create CTR mode with the nonce and counter for this block
		iv := append(nonces[b], binary.BigEndian.AppendUint32(nil, counters[b])...)
		ctr := cipher.NewCTR(block, iv)
		ctr.XORKeyStream(output[start:end], input[start:end])
	}

	circuit := &aes_v2.AESCircuit{
		AESBaseCircuit: aes_v2.AESBaseCircuit{
			Key: make([]frontend.Variable, len(key)),
		},
	}

	for i := 0; i < len(key); i++ {
		circuit.Key[i] = key[i]
	}

	// Set per-block nonce and counter from arrays
	for b := 0; b < aes_v2.BLOCKS; b++ {
		for i := 0; i < len(nonces[b]); i++ {
			circuit.Nonce[b][i] = nonces[b][i]
		}
		circuit.Counter[b] = counters[b]
	}

	for i := 0; i < len(input); i++ {
		circuit.In[i] = input[i]
	}
	for i := 0; i < len(output); i++ {
		circuit.Out[i] = output[i]
	}

	wtns, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	gProof, err := groth16.Prove(ap.r1cs, ap.pk, wtns)
	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	_, err = gProof.WriteTo(buf)
	if err != nil {
		panic(err)
	}

	return buf.Bytes(), output
}

type ChaChaOPRFProver struct {
	baseProver
}

func (cp *ChaChaOPRFProver) SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey) {
	cp.r1cs = r1cs
	cp.pk = pk
}
func (cp *ChaChaOPRFProver) Prove(params *InputParams) (proof []byte, output []uint8) {

	key, nonces, counters, oprf := params.Key, params.GetNonces(), params.GetCounters(), params.TOPRF

	if len(key) != 32 {
		log.Panicf("key length must be 32: %d", len(key))
	}
	if len(params.Blocks) != chachaV3.Blocks {
		log.Panicf("blocks array length must be %d: %d", chachaV3.Blocks, len(params.Blocks))
	}
	for i, block := range params.Blocks {
		if len(block.Nonce) != 12 {
			log.Panicf("block[%d] nonce length must be 12: %d", i, len(block.Nonce))
		}
	}

	// Handle padding based on boundaries
	boundaries := params.GetBoundaries()
	totalExpectedSize := chachaV3.Blocks * 64
	blockSize := 64 // ChaCha20 has 64-byte blocks

	// Calculate actual data size from boundaries
	actualDataSize := uint32(0)
	for _, b := range boundaries {
		actualDataSize += b
	}

	// Create padded input if necessary
	var input []byte
	if uint32(len(params.Input)) == actualDataSize && actualDataSize < uint32(totalExpectedSize) {
		// Input is unpadded, we need to pad it
		input = make([]byte, totalExpectedSize)
		srcOffset := uint32(0)
		for b := 0; b < chachaV3.Blocks; b++ {
			dstStart := b * blockSize
			copyLen := boundaries[b]
			if copyLen > 0 && srcOffset < uint32(len(params.Input)) {
				actualCopy := copyLen
				if srcOffset+actualCopy > uint32(len(params.Input)) {
					actualCopy = uint32(len(params.Input)) - srcOffset
				}
				copy(input[dstStart:dstStart+int(actualCopy)], params.Input[srcOffset:srcOffset+actualCopy])
				srcOffset += copyLen
			}
		}
	} else if len(params.Input) == totalExpectedSize {
		// Input is already padded
		input = params.Input
	} else {
		log.Panicf("input length must be %d (padded) or %d (unpadded): %d", totalExpectedSize, actualDataSize, len(params.Input))
	}

	// calculate plaintext ourselves for each block
	output = make([]byte, len(input))

	for b := 0; b < chachaV3.Blocks; b++ {
		start := b * blockSize
		end := start + blockSize

		ctr, err := chacha20.NewUnauthenticatedCipher(key, nonces[b])
		if err != nil {
			panic(err)
		}

		ctr.SetCounter(counters[b])
		ctr.XORKeyStream(output[start:end], input[start:end])
	}

	// convert input values to bits preserving byte order

	// plaintext & ciphertext are in BE order
	bInput := utils.BytesToUint32BEBits(input)
	bOutput := utils.BytesToUint32BEBits(output)

	// everything else in LE order
	bKey := utils.BytesToUint32LEBits(key)

	var resps [toprf.Threshold]twistededwards.Point
	var coeffs [toprf.Threshold]frontend.Variable
	var pubKeys [toprf.Threshold]twistededwards.Point
	var cs [toprf.Threshold]frontend.Variable
	var rs [toprf.Threshold]frontend.Variable
	idxs := make([]int, toprf.Threshold)
	for i := 0; i < toprf.Threshold; i++ {
		r := oprf.Responses[i]
		idxs[i] = int(r.Index)
		resps[i] = utils.UnmarshalTBNPoint(r.Evaluated)
		pubKeys[i] = utils.UnmarshalTBNPoint(r.PublicKeyShare)
		cs[i] = new(big.Int).SetBytes(r.C)
		rs[i] = new(big.Int).SetBytes(r.R)
	}

	for i := 0; i < toprf.Threshold; i++ {
		coeffs[i] = utils.Coeff(idxs[i], idxs)
	}

	witness := &chachaV3_oprf.ChachaTOPRFCircuit{
		TOPRF: toprf.Params{
			DomainSeparator: new(big.Int).SetBytes(oprf.DomainSeparator),
			Mask:            new(big.Int).SetBytes(oprf.Mask),
			Output:          new(big.Int).SetBytes(oprf.Output),
			Responses:       resps,
			Coefficients:    coeffs,
			SharePublicKeys: pubKeys,
			C:               cs,
			R:               rs,
		},
	}

	copy(witness.Key[:], bKey)

	// Set per-block nonce and counter from arrays
	for b := 0; b < chachaV3.Blocks; b++ {
		bNonce := utils.BytesToUint32LEBits(nonces[b])
		copy(witness.Nonce[b][:], bNonce)
		witness.Counter[b] = utils.Uint32ToBits(counters[b])
	}

	copy(witness.In[:], bInput)
	copy(witness.Out[:], bOutput)

	// Convert TOPRFParams locations to utils.Location
	locations := make([]utils.Location, len(oprf.Locations))
	totalLen := uint32(0)
	for i, loc := range oprf.Locations {
		locations[i] = utils.Location{Pos: loc.Pos, Len: loc.Len}
		totalLen += loc.Len
	}

	// Check if all boundaries are full blocks (64 bytes for ChaCha)
	allFullBlocks := true
	for _, boundary := range boundaries {
		if boundary != 64 {
			allFullBlocks = false
			break
		}
	}

	if allFullBlocks {
		// Use simple bitmask for multiple locations
		utils.SetBitmaskForLocations(witness.Bitmask[:], locations)
	} else {
		// Use boundary-aware bitmask for multiple locations with incomplete blocks
		utils.SetBitmaskForLocationsWithBoundaries(witness.Bitmask[:], locations, boundaries, 64) // ChaCha block size is 64 bytes
	}
	witness.Len = totalLen

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	gProof, err := groth16.Prove(cp.r1cs, cp.pk, wtns)
	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	_, err = gProof.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	return buf.Bytes(), nil
}

type AESOPRFProver struct {
	baseProver
}

func (ap *AESOPRFProver) SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey) {
	ap.r1cs = r1cs
	ap.pk = pk
}
func (ap *AESOPRFProver) Prove(params *InputParams) (proof []byte, output []uint8) {

	key, nonces, counters, oprf := params.Key, params.GetNonces(), params.GetCounters(), params.TOPRF

	if len(key) != 32 && len(key) != 16 {
		log.Panicf("key length must be 16 or 32: %d", len(key))
	}
	if len(params.Blocks) != aes_v2.BLOCKS {
		log.Panicf("blocks array length must be %d: %d", aes_v2.BLOCKS, len(params.Blocks))
	}
	for i, block := range params.Blocks {
		if len(block.Nonce) != 12 {
			log.Panicf("block[%d] nonce length must be 12: %d", i, len(block.Nonce))
		}
	}

	// Handle padding based on boundaries
	boundaries := params.GetBoundaries()
	totalExpectedSize := aes_v2.BLOCKS * 16
	blockSize := 16 // AES has 16-byte blocks

	// Calculate actual data size from boundaries
	actualDataSize := uint32(0)
	for _, b := range boundaries {
		actualDataSize += b
	}

	// Create padded input if necessary
	var input []byte
	if uint32(len(params.Input)) == actualDataSize && actualDataSize < uint32(totalExpectedSize) {
		// Input is unpadded, we need to pad it
		input = make([]byte, totalExpectedSize)
		srcOffset := uint32(0)
		for b := 0; b < aes_v2.BLOCKS; b++ {
			dstStart := b * blockSize
			copyLen := boundaries[b]
			if copyLen > 0 && srcOffset < uint32(len(params.Input)) {
				actualCopy := copyLen
				if srcOffset+actualCopy > uint32(len(params.Input)) {
					actualCopy = uint32(len(params.Input)) - srcOffset
				}
				copy(input[dstStart:dstStart+int(actualCopy)], params.Input[srcOffset:srcOffset+actualCopy])
				srcOffset += copyLen
			}
		}
	} else if len(params.Input) == totalExpectedSize {
		// Input is already padded
		input = params.Input
	} else {
		log.Panicf("input length must be %d (padded) or %d (unpadded): %d", totalExpectedSize, actualDataSize, len(params.Input))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	output = make([]byte, len(input))

	// Process each block with its own nonce and counter
	for b := 0; b < aes_v2.BLOCKS; b++ {
		start := b * blockSize
		end := start + blockSize
		if end > len(input) {
			end = len(input)
		}

		// Create CTR mode with the nonce and counter for this block
		iv := append(nonces[b], binary.BigEndian.AppendUint32(nil, counters[b])...)
		ctr := cipher.NewCTR(block, iv)
		ctr.XORKeyStream(output[start:end], input[start:end])
	}

	var resps [toprf.Threshold]twistededwards.Point
	var coeffs [toprf.Threshold]frontend.Variable
	var pubKeys [toprf.Threshold]twistededwards.Point
	var cs [toprf.Threshold]frontend.Variable
	var rs [toprf.Threshold]frontend.Variable
	idxs := make([]int, toprf.Threshold)
	for i := 0; i < toprf.Threshold; i++ {
		r := oprf.Responses[i]
		idxs[i] = int(r.Index)
		resps[i] = utils.UnmarshalTBNPoint(r.Evaluated)
		pubKeys[i] = utils.UnmarshalTBNPoint(r.PublicKeyShare)
		cs[i] = new(big.Int).SetBytes(r.C)
		rs[i] = new(big.Int).SetBytes(r.R)
	}

	for i := 0; i < toprf.Threshold; i++ {
		coeffs[i] = utils.Coeff(idxs[i], idxs)
	}

	circuit := &aes_v2_oprf.AESTOPRFCircuit{
		AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, len(key))},
		TOPRF: toprf.Params{
			DomainSeparator: new(big.Int).SetBytes(oprf.DomainSeparator),
			Mask:            new(big.Int).SetBytes(oprf.Mask),
			Output:          new(big.Int).SetBytes(oprf.Output),
			Responses:       resps,
			Coefficients:    coeffs,
			SharePublicKeys: pubKeys,
			C:               cs,
			R:               rs,
		},
	}

	// Convert TOPRFParams locations to utils.Location
	locations := make([]utils.Location, len(oprf.Locations))
	totalLen := uint32(0)
	for i, loc := range oprf.Locations {
		locations[i] = utils.Location{Pos: loc.Pos, Len: loc.Len}
		totalLen += loc.Len
	}

	// Check if all boundaries are full blocks (16 bytes for AES)
	allFullBlocks := true
	for _, boundary := range boundaries {
		if boundary != 16 {
			allFullBlocks = false
			break
		}
	}

	if allFullBlocks {
		// Use simple bitmask for multiple locations
		utils.SetBitmaskForLocations(circuit.Bitmask[:], locations)
	} else {
		// Use boundary-aware bitmask for multiple locations with incomplete blocks
		utils.SetBitmaskForLocationsWithBoundaries(circuit.Bitmask[:], locations, boundaries, 16) // AES block size is 16 bytes
	}
	circuit.Len = totalLen

	for i := 0; i < len(key); i++ {
		circuit.Key[i] = key[i]
	}

	// Set per-block nonce and counter from arrays
	for b := 0; b < aes_v2.BLOCKS; b++ {
		for i := 0; i < len(nonces[b]); i++ {
			circuit.Nonce[b][i] = nonces[b][i]
		}
		circuit.Counter[b] = counters[b]
	}
	for i := 0; i < len(input); i++ {
		circuit.In[i] = input[i]
	}
	for i := 0; i < len(output); i++ {
		circuit.Out[i] = output[i]
	}

	wtns, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	gProof, err := groth16.Prove(ap.r1cs, ap.pk, wtns)
	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	_, err = gProof.WriteTo(buf)
	if err != nil {
		panic(err)
	}

	return buf.Bytes(), output
}
