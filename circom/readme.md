# ZK Symmetric Crypto - Circom

## Development

1. Clone the repository
2. cd into the `circom` directory
3. Install dependencies via: `npm i`
4. Install [circom](https://docs.circom.io/getting-started/installation/)
5. Run the tests via `npm run test`

## Building the Circuit

### Prerequisites
curl, jq

Official Ptau file for bn128 with 256k max constraints can be downloaded by running
```bash
npm run download:ptau
```

Build the circuits via `ALG={alg} npm run build:circuit`.
For eg. `ALG=chacha20 npm run build:circuit`
Note: `ALG` is the same as mentioned in the first section of this readme.

### Regenerating the Verification Key

1. Generate bls12-381 parameters via `npm run generate:ptau`
2. Fix `build-circuit.sh` to use `-p bls12381` parameter
   - note: we currently use BN-128 for our circuit, but plan to switch to BLs for greater security
   - zkey and ptau file verification is disabled right now due to a bug in the latest snarkJS version 0.7.0
3. TODO