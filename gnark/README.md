<div>
    <div>
        <img src="https://raw.githubusercontent.com/reclaimprotocol/.github/main/assets/banners/Gnark.png"  />
    </div>
</div>

## Circuits

There are 3 circuits for Chacha ([v1](circuits/chacha), [v2](circuits/chachaV2), [v3](circuits/chachaV3))
2 circuits for AES ([v1](circuits/aes), [v2](circuits/aesV2))
V3 ChaCha20 and V2 AES are the most efficient implementations:

- ChaCha20 V3:
  - Operates on individual bits
  - Optimized for smaller circuit size & better overall performance

- AES V2:
  - Employs lookup tables for transformations
  - Avoids on-the-fly calculations, resulting in faster execution
  - Significantly improves efficiency compared to the previous version

These optimized versions provide the best balance of speed and resource usage for their respective algorithms.

## Libraries

[Prover library](libraries/prover) runs on Client side Android, IOS and Linux for generating proofs
[Verifier library](libraries/verifier) runs on Server side Linux (X64 and ARM64) only for verifying proofs

## Compile all circuits, generate proving and verification keys

``` sh
go run keygen/keygen.go
# to build a specific circuit
go run keygen/keygen.go --circuit chacha20
```

Do note: the key & circuit hashes need to be updated after this. TODO: automate this process

Proving keys & compiled circuits will be [here](resources/gnark)
Verification keys will be [here](libraries/verifier/impl/generated)


## Tests
```go
go test ./...
```

## Benchmarks
```go
cd libraries
go test -bench=.
```

# Build

Library files are located at:
`libraries/prover/libprove.go`
`libraries/verifier/libverify.go`

These are used to generate shared libraries for Android, IOS and Linux. They can all be built via a single script `sh scripts/build.sh`

For Linux:
```sh
# linux arm64
GOARCH=arm64 sh scripts/build.sh
# linux x86
GOARCH=x86_64 sh scripts/build.sh
# macos arm64
GOOS=darwin GOARCH=arm64 sh scripts/build.sh

# Android x86 & arm64
CC=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang CXX=android/ndk-bundle/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android30-clang++ GOOS=android GOARCH=amd64 sh scripts/build.sh
```