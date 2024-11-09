package main

import (
	"encoding/json"
	"fmt"
	"gnark-symmetric-crypto/libraries/verifier/impl"
	"gnark-symmetric-crypto/libraries/verifier/oprf"
	"unsafe"
)

// #include <stdlib.h>
import (
	"C"
)

func main() {}

//export Verify
func Verify(params []byte) bool {
	return impl.Verify(params)
}

//export VFree
func VFree(pointer unsafe.Pointer) {
	C.free(pointer)
}

//export OPRFEvaluate
func OPRFEvaluate(params []byte) (evalRes unsafe.Pointer, resLen int) {

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			bRes, er := json.Marshal(err)
			if er != nil {
				fmt.Println(er)
			} else {
				evalRes, resLen = C.CBytes(bRes), len(bRes)
			}
		}
	}()

	res := oprf.OPRFEvaluate(params)
	return C.CBytes(res), len(res)
}

//export GenerateThresholdKeys
func GenerateThresholdKeys(params []byte) (genRes unsafe.Pointer, resLen int) {

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
			bRes, er := json.Marshal(err)
			if er != nil {
				fmt.Println(er)
			} else {
				genRes, resLen = C.CBytes(bRes), len(bRes)
			}
		}
	}()

	res := oprf.TOPRFGenerateThresholdKeys(params)
	return C.CBytes(res), len(res)
}
