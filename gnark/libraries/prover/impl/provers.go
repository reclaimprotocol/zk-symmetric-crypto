package impl

import "C"
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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

const AES_BLOCKS = 4

type TOPRFResponse struct {
	Index     uint8   `json:"index"`
	PublicKey []byte  `json:"publicKey"`
	Evaluated []uint8 `json:"evaluated"`
	C         []byte  `json:"c"`
	R         []byte  `json:"r"`
}

type TOPRFParams struct {
	Pos             uint32           `json:"pos"`
	Len             uint32           `json:"len"`
	Mask            []uint8          `json:"mask"`
	DomainSeparator []uint8          `json:"domainSeparator"`
	Output          []uint8          `json:"output"`
	Responses       []*TOPRFResponse `json:"responses"`
}

type InputParams struct {
	Cipher  string       `json:"cipher"`
	Key     []uint8      `json:"key"`
	Nonce   []uint8      `json:"nonce"`
	Counter uint32       `json:"counter"`
	Input   []uint8      `json:"input"` // usually it's redacted ciphertext
	TOPRF   *TOPRFParams `json:"toprf,omitempty"`
}

type AESWrapper struct {
	Key     []frontend.Variable
	Nonce   [12]frontend.Variable              `gnark:",public"`
	Counter frontend.Variable                  `gnark:",public"`
	In      [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
	Out     [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
}

func (circuit *AESWrapper) Define(_ frontend.API) error {
	return nil
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

	key, nonce, counter, input := params.Key, params.Nonce, params.Counter, params.Input

	if len(key) != 32 {
		log.Panicf("key length must be 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(input) != 64 {
		log.Panicf("input length must be 64: %d", len(input))
	}

	// calculate output ourselves

	output = make([]byte, len(input))

	ctr, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	ctr.SetCounter(counter)
	ctr.XORKeyStream(output, input)

	// convert input values to bits preserving byte order

	// plaintext & ciphertext are in BE order
	bInput := utils.BytesToUint32BEBits(input)
	bOutput := utils.BytesToUint32BEBits(output)

	// everything else in LE order
	bKey := utils.BytesToUint32LEBits(key)
	bNonce := utils.BytesToUint32LEBits(nonce)
	bCounter := utils.Uint32ToBits(counter)

	witness := &chachaV3.ChaChaCircuit{}

	copy(witness.Key[:], bKey)
	copy(witness.Nonce[:], bNonce)
	witness.Counter = bCounter
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

	key, nonce, counter, input := params.Key, params.Nonce, params.Counter, params.Input

	if len(key) != 32 && len(key) != 16 {
		log.Panicf("key length must be 16 or 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(input) != 64 {
		log.Panicf("input length must be 64: %d", len(input))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	output = make([]byte, len(input))

	ctr := cipher.NewCTR(block, append(nonce, binary.BigEndian.AppendUint32(nil, counter)...))
	ctr.XORKeyStream(output, input)

	circuit := &AESWrapper{
		Key: make([]frontend.Variable, len(key)),
	}

	circuit.Counter = counter

	for i := 0; i < len(key); i++ {
		circuit.Key[i] = key[i]
	}
	for i := 0; i < len(nonce); i++ {
		circuit.Nonce[i] = nonce[i]
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

	key, nonce, counter, input, oprf := params.Key, params.Nonce, params.Counter, params.Input, params.TOPRF

	if len(key) != 32 {
		log.Panicf("key length must be 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(input) != chachaV3_oprf.Blocks*64 {
		log.Panicf("input length must be 64: %d", len(input))
	}

	// calculate ciphertext ourselves

	output = make([]byte, len(input))

	ctr, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	ctr.SetCounter(counter)
	ctr.XORKeyStream(output, input)

	// convert input values to bits preserving byte order

	// plaintext & ciphertext are in BE order
	bInput := utils.BytesToUint32BEBits(input)
	bOutput := utils.BytesToUint32BEBits(output)

	// everything else in LE order
	bKey := utils.BytesToUint32LEBits(key)
	bNonce := utils.BytesToUint32LEBits(nonce)
	bCounter := utils.Uint32ToBits(counter)

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
		pubKeys[i] = utils.UnmarshalTBNPoint(r.PublicKey)
		cs[i] = new(big.Int).SetBytes(r.C)
		rs[i] = new(big.Int).SetBytes(r.R)
	}

	for i := 0; i < toprf.Threshold; i++ {
		coeffs[i] = utils.Coeff(idxs[i], idxs)
	}

	witness := &chachaV3_oprf.ChachaTOPRFCircuit{
		TOPRF: chachaV3_oprf.TOPRFData{
			DomainSeparator:   new(big.Int).SetBytes(oprf.DomainSeparator),
			Mask:              new(big.Int).SetBytes(oprf.Mask),
			Output:            new(big.Int).SetBytes(oprf.Output),
			EvaluatedElements: resps,
			Coefficients:      coeffs,
			PublicKeys:        pubKeys,
			C:                 cs,
			R:                 rs,
		},
	}

	copy(witness.Key[:], bKey)
	copy(witness.Nonce[:], bNonce)
	witness.Counter = bCounter
	copy(witness.In[:], bInput)
	copy(witness.Out[:], bOutput)

	utils.SetBitmask(witness.Bitmask[:], oprf.Pos, oprf.Len)
	witness.Len = oprf.Len

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
