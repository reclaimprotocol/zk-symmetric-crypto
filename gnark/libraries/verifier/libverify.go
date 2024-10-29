package main

import (
	"gnark-symmetric-crypto/libraries/verifier/impl"
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
