package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/circuits/chachaV3_oprf"
	"regexp"
	"time"

	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const OUT_DIR = "../resources/gnark"

func main() {

	generateCircuitFiles(&chachaV3.ChaChaCircuit{}, "chacha20", "chacha20")
	generateCircuitFiles(&chachaV3_oprf.ChachaTOPRFCircuit{TOPRF: chachaV3_oprf.TOPRFData{}}, "chacha20_oprf", "chacha20-toprf")

	aes128 := &aes_v2.AES128Wrapper{
		AESWrapper: aes_v2.AESWrapper{
			Key: make([]frontend.Variable, 16),
		},
	}

	generateCircuitFiles(aes128, "aes128", "aes-128-ctr")

	aes256 := &aes_v2.AES256Wrapper{
		AESWrapper: aes_v2.AESWrapper{
			Key: make([]frontend.Variable, 32),
		},
	}
	generateCircuitFiles(aes256, "aes256", "aes-256-ctr")

}

func generateCircuitFiles(circuit frontend.Circuit, filename, algName string) {
	curve := ecc.BN254.ScalarField()

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("constraints: %d pub %d secret %d\n", r1css.GetNbConstraints(), r1css.GetNbPublicVariables(), r1css.GetNbSecretVariables())

	_ = os.Remove(OUT_DIR + "/r1cs." + filename)
	_ = os.Remove(OUT_DIR + "/pk." + filename)
	_ = os.Remove("libraries/verifier/impl/generated/vk." + filename)
	f, err := os.OpenFile(OUT_DIR+"/r1cs."+filename, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		panic(err)
	}

	buf := &bytes.Buffer{}
	_, err = r1css.WriteTo(buf)
	if err != nil {
		panic(err)
	}

	circuitHash := hashBytes(buf.Bytes())

	_, err = f.Write(buf.Bytes())
	if err != nil {
		{
			panic(err)
		}
	}

	err = f.Close()
	if err != nil {
		panic(err)
	}

	pk, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	buf = &bytes.Buffer{}
	_, err = pk.WriteTo(buf)
	if err != nil {
		panic(err)
	}
	pkHash := hashBytes(buf.Bytes())

	f2, err := os.OpenFile(OUT_DIR+"/pk."+filename, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		panic(err)
	}

	_, err = f2.Write(buf.Bytes())
	if err != nil {
		panic(err)
	}
	err = f2.Close()
	if err != nil {
		panic(err)
	}

	f3, err := os.OpenFile("libraries/verifier/impl/generated/vk."+filename, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		panic(err)
	}

	_, err = vk1.WriteTo(f3)
	if err != nil {
		panic(err)
	}
	err = f3.Close()
	if err != nil {
		panic(err)
	}

	fmt.Println("generated circuit for", filename)
	updateLibraryHashes(algName, pkHash, circuitHash)
	fmt.Println("updated hashes for", filename)
}

func hashBytes(bytes []byte) []byte {
	hash := sha256.Sum256(bytes)
	return []byte(hex.EncodeToString(hash[:]))
}

func updateLibraryHashes(algName string, pkHash, circuitHash []byte) {
	libFile, err := os.ReadFile("libraries/prover/impl/library.go")
	if err != nil {
		panic(err)
	}

	r := regexp.MustCompile("(?si)" + algName + "\":.*?KeyHash:\\s*\"([a-z0-9]{64})\".*?CircuitHash:\\s+\"([a-z0-9]{64})\"")
	libFile = replaceAllSubmatchFunc(r, libFile, func(groups [][]byte) [][]byte {
		groups[0] = pkHash
		groups[1] = circuitHash
		return groups
	}, 1)
	err = os.WriteFile("libraries/prover/impl/library.go", libFile, 0777)
	if err != nil {
		panic(err)
	}
}

// from https://gist.github.com/slimsag/14c66b88633bd52b7fa710349e4c6749
func replaceAllSubmatchFunc(re *regexp.Regexp, src []byte, repl func([][]byte) [][]byte, n int) []byte {
	var (
		result  = make([]byte, 0, len(src))
		matches = re.FindAllSubmatchIndex(src, n)
		last    = 0
	)
	for _, match := range matches {
		// Append bytes between our last match and this one (i.e. non-matched bytes).
		matchStart := match[0]
		matchEnd := match[1]
		result = append(result, src[last:matchStart]...)
		last = matchEnd

		// Determine the groups / submatch bytes and indices.
		groups := [][]byte{}
		groupIndices := [][2]int{}
		for i := 2; i < len(match); i += 2 {
			start := match[i]
			end := match[i+1]
			groups = append(groups, src[start:end])
			groupIndices = append(groupIndices, [2]int{start, end})
		}

		// Replace the groups as desired.
		groups = repl(groups)

		// Append match data.
		lastGroup := matchStart
		for i, newValue := range groups {
			// Append bytes between our last group match and this one (i.e. non-group-matched bytes)
			groupStart := groupIndices[i][0]
			groupEnd := groupIndices[i][1]
			result = append(result, src[lastGroup:groupStart]...)
			lastGroup = groupEnd

			// Append the new group value.
			result = append(result, newValue...)
		}
		result = append(result, src[lastGroup:matchEnd]...) // remaining
	}
	result = append(result, src[last:]...) // remaining
	return result
}
