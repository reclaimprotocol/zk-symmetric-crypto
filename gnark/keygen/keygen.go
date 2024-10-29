package main

import (
	aes2 "gnark-symmetric-crypto/circuits/aesV2"
	"gnark-symmetric-crypto/circuits/chachaV3"
	"time"

	"fmt"
	"os"

	// _ "net/http/pprof"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const GEN_FILES_DIR = "../resources/gnark/"

func main() {
	generateChaChaV3()
	generateAES128()
	generateAES256()
}

func generateChaChaV3() {
	curve := ecc.BN254.ScalarField()

	witness := chachaV3.ChaChaCircuit{}

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("Blocks: %d, constraints: %d\n", chachaV3.Blocks, r1css.GetNbConstraints())

	os.Remove(GEN_FILES_DIR + "r1cs.chacha20")
	os.Remove(GEN_FILES_DIR + "pk.chacha20")
	os.Remove("libraries/verifier/impl/generated/vk.chacha20")
	f, err := os.OpenFile(GEN_FILES_DIR+"r1cs.chacha20", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	f2, err := os.OpenFile(GEN_FILES_DIR+"pk.chacha20", os.O_RDWR|os.O_CREATE, 0777)
	pk1.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("libraries/verifier/impl/generated/vk.chacha20", os.O_RDWR|os.O_CREATE, 0777)
	vk1.WriteTo(f3)
	f3.Close()
}

func generateAES128() {
	curve := ecc.BN254.ScalarField()

	witness := aes2.AES128Wrapper{
		AESWrapper: aes2.AESWrapper{
			Key: make([]frontend.Variable, 16),
		},
	}

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())

	os.Remove(GEN_FILES_DIR + "r1cs.aes128")
	os.Remove(GEN_FILES_DIR + "pk.aes128")
	os.Remove("libraries/verifier/impl/generated/vk.aes128")
	f, err := os.OpenFile(GEN_FILES_DIR+"r1cs.aes128", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	f2, err := os.OpenFile(GEN_FILES_DIR+"pk.aes128", os.O_RDWR|os.O_CREATE, 0777)
	pk1.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("libraries/verifier/impl/generated/vk.aes128", os.O_RDWR|os.O_CREATE, 0777)
	vk1.WriteTo(f3)
	f3.Close()
}

func generateAES256() {
	curve := ecc.BN254.ScalarField()

	witness := aes2.AES256Wrapper{
		AESWrapper: aes2.AESWrapper{
			Key: make([]frontend.Variable, 32),
		},
	}

	t := time.Now()
	r1css, err := frontend.Compile(curve, r1cs.NewBuilder, &witness)
	if err != nil {
		panic(err)
	}
	fmt.Println("compile took ", time.Since(t))

	fmt.Printf("constraints: %d\n", r1css.GetNbConstraints())

	os.Remove(GEN_FILES_DIR + "r1cs.aes256")
	os.Remove(GEN_FILES_DIR + "pk.aes256")
	os.Remove("libraries/verifier/impl/generated/vk.aes256")
	f, err := os.OpenFile(GEN_FILES_DIR+"r1cs.aes256", os.O_RDWR|os.O_CREATE, 0777)
	r1css.WriteTo(f)
	f.Close()

	pk1, vk1, err := groth16.Setup(r1css)
	if err != nil {
		panic(err)
	}

	f2, err := os.OpenFile(GEN_FILES_DIR+"pk.aes256", os.O_RDWR|os.O_CREATE, 0777)
	pk1.WriteTo(f2)
	f2.Close()

	f3, err := os.OpenFile("libraries/verifier/impl/generated/vk.aes256", os.O_RDWR|os.O_CREATE, 0777)
	vk1.WriteTo(f3)
	f3.Close()
}

func fetchFile(keyName string) []byte {
	f, err := os.ReadFile(GEN_FILES_DIR + "" + keyName)
	if err != nil {
		panic(err)
	}
	return f
}
