package impl

import (
	"bytes"
	"encoding/json"
	"fmt"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	aes_v2_oprf "gnark-symmetric-crypto/circuits/aesV2_oprf"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/circuits/chachaV3_oprf"
	"gnark-symmetric-crypto/circuits/toprf"
	"gnark-symmetric-crypto/utils"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type Verifier interface {
	Verify(proof []byte, publicSignals json.RawMessage) bool
}

type ChachaVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaVerifier) Verify(proof []byte, publicSignals json.RawMessage) bool {
	// Parse the JSON public signals
	var signals PublicSignalsJSON
	err := json.Unmarshal(publicSignals, &signals)
	if err != nil {
		fmt.Printf("failed to parse public signals JSON: %v\n", err)
		return false
	}

	// Validate input sizes
	chunkLen := 64 * chachaV3.Blocks
	if len(signals.Ciphertext) != chunkLen {
		fmt.Printf("ciphertext must be %d bytes, not %d\n", chunkLen, len(signals.Ciphertext))
		return false
	}
	if len(signals.Input) != chunkLen {
		fmt.Printf("input must be %d bytes, not %d\n", chunkLen, len(signals.Input))
		return false
	}
	if len(signals.Blocks) != chachaV3.Blocks {
		fmt.Printf("blocks array must have %d elements, not %d\n", chachaV3.Blocks, len(signals.Blocks))
		return false
	}

	witness := &chachaV3.ChaChaCircuit{}

	// Set nonces and counters for each block
	for b := 0; b < chachaV3.Blocks; b++ {
		if len(signals.Blocks[b].Nonce) != 12 {
			fmt.Printf("block[%d] nonce must be 12 bytes, not %d\n", b, len(signals.Blocks[b].Nonce))
			return false
		}
		nonce := utils.BytesToUint32LEBits(signals.Blocks[b].Nonce)
		copy(witness.Nonce[b][:], nonce)
		witness.Counter[b] = utils.Uint32ToBits(signals.Blocks[b].Counter)
	}

	// Set input and output (ciphertext)
	out := utils.BytesToUint32BEBits(signals.Ciphertext)
	in := utils.BytesToUint32BEBits(signals.Input)

	copy(witness.In[:], in)
	copy(witness.Out[:], out)

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, cv.vk, wtns)
	if err != nil {
		fmt.Println(err)
	}
	return err == nil
}

type AESVerifier struct {
	vk groth16.VerifyingKey
}

func (av *AESVerifier) Verify(bProof []byte, publicSignals json.RawMessage) bool {
	// Parse the JSON public signals
	var signals PublicSignalsJSON
	err := json.Unmarshal(publicSignals, &signals)
	if err != nil {
		fmt.Printf("failed to parse public signals JSON: %v\n", err)
		return false
	}

	// Validate input sizes
	bytesPerInput := aes_v2.BLOCKS * 16
	if len(signals.Ciphertext) != bytesPerInput {
		fmt.Printf("ciphertext must be %d bytes, not %d\n", bytesPerInput, len(signals.Ciphertext))
		return false
	}
	if len(signals.Input) != bytesPerInput {
		fmt.Printf("input must be %d bytes, not %d\n", bytesPerInput, len(signals.Input))
		return false
	}
	if len(signals.Blocks) != aes_v2.BLOCKS {
		fmt.Printf("blocks array must have %d elements, not %d\n", aes_v2.BLOCKS, len(signals.Blocks))
		return false
	}

	witness := &aes_v2.AESCircuit{
		AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, 1)}, // avoid warnings
	}

	// Set nonces and counters for each block
	for b := 0; b < aes_v2.BLOCKS; b++ {
		if len(signals.Blocks[b].Nonce) != 12 {
			fmt.Printf("block[%d] nonce must be 12 bytes, not %d\n", b, len(signals.Blocks[b].Nonce))
			return false
		}
		for i := 0; i < 12; i++ {
			witness.Nonce[b][i] = signals.Blocks[b].Nonce[i]
		}
		witness.Counter[b] = signals.Blocks[b].Counter
	}

	// Set input (plaintext) and output (ciphertext)
	for i := 0; i < len(signals.Input); i++ {
		witness.In[i] = signals.Input[i]
		witness.Out[i] = signals.Ciphertext[i]
	}

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(bProof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, av.vk, wtns)
	if err != nil {
		fmt.Println(err)
		return false
	}

	return true
}

type ChachaOPRFVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *ChachaOPRFVerifier) Verify(proof []byte, publicSignals json.RawMessage) bool {
	var iParams *InputTOPRFParams
	err := json.Unmarshal(publicSignals, &iParams)
	if err != nil {
		fmt.Println(err)
		return false
	}

	oprf := iParams.TOPRF
	if oprf == nil || oprf.Responses == nil {
		fmt.Println("TOPRF params are empty")
		return false
	}

	resps := oprf.Responses
	if len(resps) != toprf.Threshold {
		fmt.Println("TOPRF params are invalid")
		return false
	}

	var nodePublicKeys [toprf.Threshold]twistededwards.Point
	var evals [toprf.Threshold]twistededwards.Point
	var cs [toprf.Threshold]frontend.Variable
	var rs [toprf.Threshold]frontend.Variable
	var coeffs [toprf.Threshold]frontend.Variable

	idxs := make([]int, toprf.Threshold)
	for i := 0; i < toprf.Threshold; i++ {
		idxs[i] = int(resps[i].Index)
	}

	for i := 0; i < toprf.Threshold; i++ {
		resp := resps[i]
		nodePublicKeys[i] = utils.UnmarshalPoint(resp.PublicKeyShare)
		evals[i] = utils.UnmarshalPoint(resp.Evaluated)
		cs[i] = new(big.Int).SetBytes(resp.C)
		rs[i] = new(big.Int).SetBytes(resp.R)
		coeffs[i] = utils.Coeff(idxs[i], idxs)
	}

	witness := &chachaV3_oprf.ChachaTOPRFCircuit{
		TOPRF: toprf.Params{
			DomainSeparator: new(big.Int).SetBytes(oprf.DomainSeparator),
			Responses:       evals,
			Coefficients:    coeffs,
			SharePublicKeys: nodePublicKeys,
			C:               cs,
			R:               rs,
			Output:          new(big.Int).SetBytes(oprf.Output),
		},
	}

	// Set per-block nonce and counter from arrays
	for b := 0; b < chachaV3.Blocks; b++ {
		if b >= len(iParams.Blocks) {
			fmt.Printf("Invalid blocks array length\n")
			return false
		}
		nonce := utils.BytesToUint32LEBits(iParams.Blocks[b].Nonce)
		copy(witness.Nonce[b][:], nonce)
		witness.Counter[b] = utils.Uint32ToBits(iParams.Blocks[b].Counter)
	}

	// Handle padding based on boundaries
	boundaries := make([]uint32, len(iParams.Blocks))
	totalExpectedSize := chachaV3.Blocks * 64
	blockSize := uint32(64) // ChaCha20 has 64-byte blocks

	// Calculate actual data size and boundaries
	actualDataSize := uint32(0)
	hasCustomBoundaries := false
	for i, block := range iParams.Blocks {
		if block.Boundary != nil {
			boundaries[i] = *block.Boundary
			actualDataSize += *block.Boundary
			if *block.Boundary != blockSize {
				hasCustomBoundaries = true
			}
		} else {
			boundaries[i] = blockSize
			actualDataSize += blockSize
		}
	}

	// Create padded input if necessary
	var paddedInput []byte
	if uint32(len(iParams.Input)) == actualDataSize && actualDataSize < uint32(totalExpectedSize) {
		// Input is unpadded, we need to pad it
		paddedInput = make([]byte, totalExpectedSize)
		srcOffset := uint32(0)
		for b := 0; b < chachaV3.Blocks; b++ {
			dstStart := uint32(b) * blockSize
			copyLen := boundaries[b]
			if copyLen > 0 && srcOffset < uint32(len(iParams.Input)) {
				actualCopy := copyLen
				if srcOffset+actualCopy > uint32(len(iParams.Input)) {
					actualCopy = uint32(len(iParams.Input)) - srcOffset
				}
				copy(paddedInput[dstStart:dstStart+actualCopy], iParams.Input[srcOffset:srcOffset+actualCopy])
				srcOffset += copyLen
			}
		}
	} else if len(iParams.Input) == totalExpectedSize {
		// Input is already padded
		paddedInput = iParams.Input
	} else {
		fmt.Printf("Invalid input length: expected %d (padded) or %d (unpadded), got %d\n", totalExpectedSize, actualDataSize, len(iParams.Input))
		return false
	}

	copy(witness.In[:], utils.BytesToUint32BEBits(paddedInput))

	// Convert verifier locations to utils.Location
	locations := make([]utils.Location, len(oprf.Locations))
	totalLen := uint32(0)
	for i, loc := range oprf.Locations {
		locations[i] = utils.Location{Pos: loc.Pos, Len: loc.Len}
		totalLen += loc.Len
	}

	if hasCustomBoundaries {
		utils.SetBitmaskForLocationsWithBoundaries(witness.Bitmask[:], locations, boundaries, blockSize)
	} else {
		utils.SetBitmaskForLocations(witness.Bitmask[:], locations)
	}
	witness.Len = totalLen

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, cv.vk, wtns)
	if err != nil {
		fmt.Println(err)
	}
	return err == nil
}

type AESOPRFVerifier struct {
	vk groth16.VerifyingKey
}

func (cv *AESOPRFVerifier) Verify(proof []byte, publicSignals json.RawMessage) bool {
	var iParams *InputTOPRFParams
	err := json.Unmarshal(publicSignals, &iParams)
	if err != nil {
		fmt.Println(err)
		return false
	}

	oprf := iParams.TOPRF
	if oprf == nil || oprf.Responses == nil {
		fmt.Println("TOPRF params are empty")
		return false
	}

	resps := oprf.Responses
	if len(resps) != toprf.Threshold {
		fmt.Println("TOPRF params are invalid")
		return false
	}

	var nodePublicKeys [toprf.Threshold]twistededwards.Point
	var evals [toprf.Threshold]twistededwards.Point
	var cs [toprf.Threshold]frontend.Variable
	var rs [toprf.Threshold]frontend.Variable
	var coeffs [toprf.Threshold]frontend.Variable

	idxs := make([]int, toprf.Threshold)
	for i := 0; i < toprf.Threshold; i++ {
		idxs[i] = int(resps[i].Index)
	}

	for i := 0; i < toprf.Threshold; i++ {
		resp := resps[i]
		nodePublicKeys[i] = utils.UnmarshalPoint(resp.PublicKeyShare)
		evals[i] = utils.UnmarshalPoint(resp.Evaluated)
		cs[i] = new(big.Int).SetBytes(resp.C)
		rs[i] = new(big.Int).SetBytes(resp.R)
		coeffs[i] = utils.Coeff(idxs[i], idxs)
	}

	witness := &aes_v2_oprf.AESTOPRFCircuit{
		AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, 1)}, // avoid warnings
		TOPRF: toprf.Params{
			DomainSeparator: new(big.Int).SetBytes(oprf.DomainSeparator),
			Responses:       evals,
			Coefficients:    coeffs,
			SharePublicKeys: nodePublicKeys,
			C:               cs,
			R:               rs,
			Output:          new(big.Int).SetBytes(oprf.Output),
		},
	}

	// Set per-block nonce and counter from arrays
	for b := 0; b < aes_v2.BLOCKS; b++ {
		if b >= len(iParams.Blocks) {
			fmt.Printf("Invalid blocks array length\n")
			return false
		}
		for i := 0; i < len(iParams.Blocks[b].Nonce); i++ {
			witness.Nonce[b][i] = iParams.Blocks[b].Nonce[i]
		}
		witness.Counter[b] = iParams.Blocks[b].Counter
	}

	// Handle padding based on boundaries
	boundaries := make([]uint32, len(iParams.Blocks))
	totalExpectedSize := aes_v2.BLOCKS * 16
	blockSize := uint32(16) // AES has 16-byte blocks

	// Calculate actual data size and boundaries
	actualDataSize := uint32(0)
	hasCustomBoundaries := false
	for i, block := range iParams.Blocks {
		if block.Boundary != nil {
			boundaries[i] = *block.Boundary
			actualDataSize += *block.Boundary
			if *block.Boundary != blockSize {
				hasCustomBoundaries = true
			}
		} else {
			boundaries[i] = blockSize
			actualDataSize += blockSize
		}
	}

	// Create padded input if necessary
	var paddedInput []byte
	if uint32(len(iParams.Input)) == actualDataSize && actualDataSize < uint32(totalExpectedSize) {
		// Input is unpadded, we need to pad it
		paddedInput = make([]byte, totalExpectedSize)
		srcOffset := uint32(0)
		for b := 0; b < aes_v2.BLOCKS; b++ {
			dstStart := uint32(b) * blockSize
			copyLen := boundaries[b]
			if copyLen > 0 && srcOffset < uint32(len(iParams.Input)) {
				actualCopy := copyLen
				if srcOffset+actualCopy > uint32(len(iParams.Input)) {
					actualCopy = uint32(len(iParams.Input)) - srcOffset
				}
				copy(paddedInput[dstStart:dstStart+actualCopy], iParams.Input[srcOffset:srcOffset+actualCopy])
				srcOffset += copyLen
			}
		}
	} else if len(iParams.Input) == totalExpectedSize {
		// Input is already padded
		paddedInput = iParams.Input
	} else {
		fmt.Printf("Invalid input length: expected %d (padded) or %d (unpadded), got %d\n", totalExpectedSize, actualDataSize, len(iParams.Input))
		return false
	}

	for i := 0; i < len(paddedInput); i++ {
		witness.In[i] = paddedInput[i]
	}

	// Convert verifier locations to utils.Location
	locations := make([]utils.Location, len(oprf.Locations))
	totalLen := uint32(0)
	for i, loc := range oprf.Locations {
		locations[i] = utils.Location{Pos: loc.Pos, Len: loc.Len}
		totalLen += loc.Len
	}

	if hasCustomBoundaries {
		utils.SetBitmaskForLocationsWithBoundaries(witness.Bitmask[:], locations, boundaries, blockSize)
	} else {
		utils.SetBitmaskForLocations(witness.Bitmask[:], locations)
	}
	witness.Len = totalLen

	wtns, err := frontend.NewWitness(witness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		fmt.Println(err)
		return false
	}

	gProof := groth16.NewProof(ecc.BN254)
	_, err = gProof.ReadFrom(bytes.NewBuffer(proof))
	if err != nil {
		fmt.Println(err)
		return false
	}
	err = groth16.Verify(gProof, cv.vk, wtns)
	if err != nil {
		fmt.Println(err)
	}
	return err == nil
}
