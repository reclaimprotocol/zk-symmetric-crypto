export type NoirWitnessInput = {
	key: number[]
	counter?: number[] | number
	plaintext: number[]
	expected_ciphertext: number[]
	// ChaCha20 specific fields
	ciphertext?: number[]
	nonce?: number[]
}

export type BarretenbergOpts = {
         threads?: number
  }