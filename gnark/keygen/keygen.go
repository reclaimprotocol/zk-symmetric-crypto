package main

import (
	"gnark-symmetric-crypto/circuits/chachaV3_oprf"
	"time"

	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {

	// generateCircuitFiles(&chachaV3.ChaChaCircuit{}, "chacha20")
	generateCircuitFiles(&chachaV3_oprf.ChachaTOPRFCircuit{TOPRF: chachaV3_oprf.TOPRFData{}}, "chacha20_oprf")

	/*aes128 := &aesv2.AES128Wrapper{
		AESWrapper: aesv2.AESWrapper{
			Key: make([]frontend.Variable, 16),
		},
	}

	generateCircuitFiles(aes128, "aes128")

	aes256 := &aesv2.AES256Wrapper{
		AESWrapper: aesv2.AESWrapper{
			Key: make([]frontend.Variable, 32),
		},
	}
	generateCircuitFiles(aes256, "aes256")*/

}

func generateCircuitFiles(circuit frontend.Circuit, name string) {
	curve := ecc.BN254.ScalarField()

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("constraints: %d pub %d secret %d\n", r1css.GetNbConstraints(), r1css.GetNbPublicVariables(), r1css.GetNbSecretVariables())

	_ = os.Remove("circuits/generated/r1cs." + name)
	_ = os.Remove("circuits/generated/pk." + name)
	_ = os.Remove("libraries/verifier/impl/generated/vk." + name)
	f, err := os.OpenFile("circuits/generated/r1cs."+name, os.O_RDWR|os.O_CREATE, 0777)
	_, err = r1css.WriteTo(f)
	if err != nil {
		panic(err)
	}
	err = f.Close()
	if err != nil {
		panic(err)
	}

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	f2, err := os.OpenFile("circuits/generated/pk."+name, os.O_RDWR|os.O_CREATE, 0777)
	_, err = pk1.WriteTo(f2)
	if err != nil {
		panic(err)
	}
	err = f2.Close()
	if err != nil {
		panic(err)
	}

	f3, err := os.OpenFile("libraries/verifier/impl/generated/vk."+name, os.O_RDWR|os.O_CREATE, 0777)
	_, err = vk1.WriteTo(f3)
	if err != nil {
		panic(err)
	}
	err = f3.Close()
	if err != nil {
		panic(err)
	}
}
