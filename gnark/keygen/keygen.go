package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	aes_v2 "gnark-symmetric-crypto/circuits/aesV2"
	aes_v2_oprf "gnark-symmetric-crypto/circuits/aesV2_oprf"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"gnark-symmetric-crypto/circuits/chachaV3_oprf"
	"gnark-symmetric-crypto/circuits/toprf"
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

type algCircuit struct {
	alg     string
	circuit frontend.Circuit
}

var algMappings = map[string]*algCircuit{
	"chacha20":      {"chacha20", &chachaV3.ChaChaCircuit{}},
	"aes128":        {"aes-128-ctr", &aes_v2.AESCircuit{AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, 16)}}},
	"aes256":        {"aes-256-ctr", &aes_v2.AESCircuit{AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, 32)}}},
	"chacha20_oprf": {"chacha20-toprf", &chachaV3_oprf.ChachaTOPRFCircuit{TOPRF: toprf.Params{}}},
	"aes128_oprf":   {"aes-128-ctr-toprf", &aes_v2_oprf.AESTOPRFCircuit{AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, 16)}, TOPRF: toprf.Params{}}},
	"aes256_oprf":   {"aes-256-ctr-toprf", &aes_v2_oprf.AESTOPRFCircuit{AESBaseCircuit: aes_v2.AESBaseCircuit{Key: make([]frontend.Variable, 32)}, TOPRF: toprf.Params{}}},
}

func main() {
	for alg, circuit := range algMappings {
		generateCircuitFiles(circuit.circuit, alg)
	}
}

func generateCircuitFiles(circuit frontend.Circuit, name string) {
	circuitArg, err := getArg("--circuit")
	if err == nil {
		if circuitArg != name {
			fmt.Println("skipping circuit ", name)
			return
		}
	}

	curve := ecc.BN254.ScalarField()

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("constraints: %d pub %d secret %d\n", r1css.GetNbConstraints(), r1css.GetNbPublicVariables(), r1css.GetNbSecretVariables())

	_ = os.Remove(OUT_DIR + "/r1cs." + name)
	_ = os.Remove(OUT_DIR + "/pk." + name)
	_ = os.Remove("libraries/verifier/impl/generated/vk." + name)
	f, err := os.OpenFile(OUT_DIR+"/r1cs."+name, os.O_RDWR|os.O_CREATE, 0777)
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

	f2, err := os.OpenFile(OUT_DIR+"/pk."+name, os.O_RDWR|os.O_CREATE, 0777)
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

	f3, err := os.OpenFile("libraries/verifier/impl/generated/vk."+name, os.O_RDWR|os.O_CREATE, 0777)
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

	fmt.Println("generated circuit for", name)
	updateLibraryHashes(algMappings[name].alg, pkHash, circuitHash)
	fmt.Println("updated hashes for", name)
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

/**
 * Helper function to get the value of a command line argument
 * Expects args in the form of "[name] [value]"
 */
func getArg(name string) (string, error) {
	for i, arg := range os.Args {
		if arg == name {
			if i+1 < len(os.Args) {
				return os.Args[i+1], nil
			}

			return "", fmt.Errorf("arg %s has no value", name)
		}
	}

	return "", fmt.Errorf("arg %s not found", name)
}
