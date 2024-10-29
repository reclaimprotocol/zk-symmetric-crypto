# ZK Symmetric Crypto - JS

The JS (typescript really) package for generating & verifying ZK proofs for symmetric encryption, on the browser or NodeJS.

## Install

``` sh
npm i @reclaimprotocol/zk-symmetric-crypto
```

The individual backends are optional dependencies. You can install them as needed.
For `snarkjs`: `npm i snarkjs`
For `gnark`: `npm i koffi`
	- Also ensure you download the `gnark` binaries. See [here](#obtaining-files-locally)
	- Note: `gnark` is not supported on the browser.
	- Note: `gnark` binaries are only built for `linux` - `x86_64` & `arm64`
For `expander`: No additional dependencies needed

## Usage

### Generating & Verifying Proofs

```ts
import { generateProof, verifyProof, makeSnarkJsZkOperator } from '@reclaimprotocol/zk-symmetric-crypto'
import { createCipheriv, randomBytes } from 'crypto'

async function main() {
	const key = randomBytes(32)
	const iv = randomBytes(12)
	const algorithm = 'chacha20'
	const data = 'Hello World!'

	const cipher = createCipheriv('chacha20-poly1305', key, iv)
	const ciphertext = Buffer.concat([
		cipher.update(data),
		cipher.final()
	])

	// the operator is the abstract interface for
	// the snarkjs library to generate & verify the proof
	const operator = makeLocalSnarkJsZkOperator(algorithm)
	// generate the proof that you have the key to the ciphertext
	const {
		// groth16-snarkjs proof as a JSON string
		proofJson,
		// the plaintext, obtained from the output of the circuit
		plaintext,
	} = await generateProof({
		algorithm,
		// key, iv & counter are the private inputs to the circuit
		privateInput: {
			key,
			iv,
			// this is the counter from which to start
			// the stream cipher. Read about
			// the counter here: https://en.wikipedia.org/wiki/Stream_cipher
			offset: 0
		},
		// the public ciphertext input to the circuit
		publicInput: { ciphertext },
		operator,
	})

	// you can check that the plaintext obtained from the circuit
	// is the same as the plaintext obtained from the ciphertext
	const plaintextBuffer = plaintext
		// slice in case the plaintext was padded
		.slice(0, data.length)
	// "Hello World!"
	console.log(Buffer.from(plaintextBuffer).toString())

	// you can verify the proof with the public inputs
	// and the proof JSON string
	await verifyProof({
		proof: {
			proofJson,
			plaintext,
			algorithm
		},
		// the public inputs to the circuit
		publicInput: { ciphertext },
		operator
	})
	console.log('Proof verified')
}

main()
```

### Obtaining Files Locally

Since the proving keys, binaries, circuits etc. are quite large, they aren't included by default in this package. Instead, the package will remotely fetch them as needed from this repository.

**Limitations of Remote Fetching**:
- `gnark` requires the binaries to be present locally. So the files need to be present in the `bin` folder of the repo.
- It can of course be quite a pain to keep downloading dozens of MBs of files every time you run your code, especially when you're developing.

Thus, to overcome this, you can locally download the files & use the local file fetching by running the script:
``` sh
node node_modules/@reclaimprotocol/zk-symmetric-crypto/lib/scripts/download-files
```

Now, you can use the `local file fetcher` right out of the box.

Do keep in mind, if you update the package, you will need to run this script again. This is intentional as newer versions of the package may need newer files or just may not be compatible with the old ones

## Local Dev

1. Of course, clone the repo
2. `cd` into this directory (`js`)
3. `npm i`
4. `npm run test` to run the tests

Note: just FYI, the circuit files are symlinked to the root of the repo (i.e. `resources` & `bin` folders). So during local dev, the default local fetching works right out of the box.

To publish the package, we've a Github Action that will build the package & publish it to the Github Package Registry. It can be manually triggered by running the workflow `Publish to NPM` in the Actions tab.