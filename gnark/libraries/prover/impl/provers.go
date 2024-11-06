package impl

import "C"
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"gnark-symmetric-crypto/utils"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/chacha20"
)

func init() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	// std.RegisterHints()
}

const BITS_PER_WORD = 32
const BLOCKS = 1
const AES_BLOCKS = 4

type ChaChaCircuit struct {
	Key     [8][BITS_PER_WORD]frontend.Variable
	Counter [BITS_PER_WORD]frontend.Variable              `gnark:",public"`
	Nonce   [3][BITS_PER_WORD]frontend.Variable           `gnark:",public"`
	In      [16 * BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
	Out     [16 * BLOCKS][BITS_PER_WORD]frontend.Variable `gnark:",public"`
}

func (c *ChaChaCircuit) Define(_ frontend.API) error {
	return nil
}

type AESWrapper struct {
	Key        []frontend.Variable
	Nonce      [12]frontend.Variable              `gnark:",public"`
	Counter    frontend.Variable                  `gnark:",public"`
	Plaintext  [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
	Ciphertext [AES_BLOCKS * 16]frontend.Variable `gnark:",public"`
}

func (circuit *AESWrapper) Define(_ frontend.API) error {
	return nil
}

type InputParams struct {
	Cipher  string  `json:"cipher"`
	Key     []uint8 `json:"key"`
	Nonce   []uint8 `json:"nonce"`
	Counter uint32  `json:"counter"`
	Input   []uint8 `json:"input"`
}

type Prover interface {
	SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey)
	Prove(params *InputParams) (proof []byte, ciphertext []uint8)
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
func (cp *ChaChaProver) proveChaCha(key []uint8, nonce []uint8, counter uint32, plaintext []uint8) (proof []byte, ct []uint8) {

	if len(key) != 32 {
		log.Panicf("key length must be 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 64 {
		log.Panicf("plaintext length must be 64: %d", len(plaintext))
	}

	// calculate ciphertext ourselves

	ct = make([]byte, len(plaintext))

	ctr, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	ctr.SetCounter(counter)
	ctr.XORKeyStream(ct, plaintext)

	// convert input values to bits preserving byte order

	// plaintext & ciphertext are in BE order
	bPlaintext := utils.BytesToUint32BEBits(plaintext)
	bCiphertext := utils.BytesToUint32BEBits(ct)

	// everything else in LE order
	bKey := utils.BytesToUint32LEBits(key)
	bNonce := utils.BytesToUint32LEBits(nonce)
	bCounter := utils.Uint32ToBits(counter)

	witness := &ChaChaCircuit{}

	for i := 0; i < len(witness.Key); i++ {
		for j := 0; j < len(witness.Key[i]); j++ {
			witness.Key[i][j] = bKey[i][j]
		}
	}

	for i := 0; i < len(witness.Nonce); i++ {
		for j := 0; j < len(witness.Nonce[i]); j++ {
			witness.Nonce[i][j] = bNonce[i][j]
		}
	}

	for i := 0; i < len(witness.Counter); i++ {
		witness.Counter[i] = bCounter[i]
	}

	for i := 0; i < len(witness.In); i++ {
		for j := 0; j < len(witness.In[i]); j++ {
			witness.In[i][j] = bPlaintext[i][j]
		}
	}

	for i := 0; i < len(witness.Out); i++ {
		for j := 0; j < len(witness.Out[i]); j++ {
			witness.Out[i][j] = bCiphertext[i][j]
		}
	}

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
	return buf.Bytes(), ct
}
func (cp *ChaChaProver) Prove(params *InputParams) (proof []byte, ciphertext []uint8) {

	return cp.proveChaCha(params.Key, params.Nonce, params.Counter, params.Input)
}

type AESProver struct {
	baseProver
}

func (ap *AESProver) SetParams(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey) {
	ap.r1cs = r1cs
	ap.pk = pk
}
func (ap *AESProver) proveAES(key []uint8, nonce []uint8, counter uint32, plaintext []uint8) (proof []byte, ct []uint8) {

	if len(key) != 32 && len(key) != 16 {
		log.Panicf("key length must be 16 or 32: %d", len(key))
	}
	if len(nonce) != 12 {
		log.Panicf("nonce length must be 12: %d", len(nonce))
	}
	if len(plaintext) != 64 {
		log.Panicf("plaintext length must be 64: %d", len(plaintext))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))

	ctr := cipher.NewCTR(block, append(nonce, binary.BigEndian.AppendUint32(nil, counter)...))
	ctr.XORKeyStream(ciphertext, plaintext)

	circuit := &AESWrapper{
		Key: make([]frontend.Variable, len(key)),
	}

	for i := 0; i < len(key); i++ {
		circuit.Key[i] = key[i]
	}
	for i := 0; i < len(circuit.Nonce); i++ {
		circuit.Nonce[i] = nonce[i]
	}
	circuit.Counter = counter
	for i := 0; i < len(plaintext); i++ {
		circuit.Plaintext[i] = plaintext[i]
	}
	for i := 0; i < len(ciphertext); i++ {
		circuit.Ciphertext[i] = ciphertext[i]
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

	return buf.Bytes(), ciphertext
}
func (ap *AESProver) Prove(params *InputParams) (proof []byte, ciphertext []uint8) {
	return ap.proveAES(params.Key, params.Nonce, params.Counter, params.Input)
}
