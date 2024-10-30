package main

import (
	"fmt"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"os"

	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo"
	"github.com/consensys/gnark-crypto/ecc"
)

const GEN_FILES_DIR = "../resources/expander/"

var CURVE = ecc.BN254.ScalarField()

func main() {
	err := generateChaChaV3()
	if err != nil {
		panic(err)
	}
}

func generateChaChaV3() error {
	circuit, err := ecgo.Compile(ecc.BN254.ScalarField(), &chachaV3.ChaChaCircuit{})
	if err != nil {
		return err
	}

	c := circuit.GetLayeredCircuit()

	circuitfilename := GEN_FILES_DIR + "chacha20.txt"
	err = os.WriteFile(circuitfilename, c.Serialize(), 0o644)
	if err != nil {
		return err
	}

	fmt.Printf("generated circuit file: %s\n", circuitfilename)

	return nil
}
