package main

import (
	"encoding/json"
	"fmt"
	"gnark-symmetric-crypto/libraries/prover/impl"
	"gnark-symmetric-crypto/libraries/prover/oprf"
	"unsafe"
)

// #include <stdlib.h>
import (
	"C"
)

func main() {}

//export enforce_binding
func enforce_binding() {}

//export InitAlgorithm
func InitAlgorithm(algorithmID uint8, provingKey []byte, r1cs []byte) bool {
	return impl.InitAlgorithm(algorithmID, provingKey, r1cs)
}

//export Free
func Free(pointer unsafe.Pointer) {
	C.free(pointer)
}

//export Prove
func Prove(params []byte) (proofRes unsafe.Pointer, resLen int) {

	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("%+v", err)
			bRes, er := json.Marshal(err)
			if er != nil {
				fmt.Println(er)
			} else {
				proofRes, resLen = C.CBytes(bRes), len(bRes)
			}
		}
	}()

	res := impl.Prove(params)
	return C.CBytes(res), len(res)
}

//export GenerateOPRFRequestData
func GenerateOPRFRequestData(params []byte) (proofRes unsafe.Pointer, resLen int) {

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			bRes, er := json.Marshal(err)
			if er != nil {
				fmt.Println(er)
			} else {
				proofRes, resLen = C.CBytes(bRes), len(bRes)
			}
		}
	}()

	res := oprf.GenerateOPRFRequestData(params)
	return C.CBytes(res), len(res)
}

//export TOPRFFinalize
func TOPRFFinalize(params []byte) (proofRes unsafe.Pointer, resLen int) {

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			bRes, er := json.Marshal(err)
			if er != nil {
				fmt.Println(er)
			} else {
				proofRes, resLen = C.CBytes(bRes), len(bRes)
			}
		}
	}()

	res := oprf.TOPRFFinalize(params)
	return C.CBytes(res), len(res)
}
