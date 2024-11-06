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

//export OPRF
func OPRF(params []byte) (proofRes unsafe.Pointer, resLen int) {

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

	res := oprf.OPRFEvaluate(params)
	return C.CBytes(res), len(res)
}

//export TOPRFGenerateSharedKey
func TOPRFGenerateSharedKey(params []byte) (proofRes unsafe.Pointer, resLen int) {

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

	res := oprf.TOPRFGenerateSharedKey(params)
	return C.CBytes(res), len(res)
}
