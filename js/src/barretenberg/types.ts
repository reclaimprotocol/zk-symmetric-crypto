export type NoirWitnessInput = {
	key: number[]
	counter: number[]
	plaintext: number[]
	expected_ciphertext: number[]
}

export type BarretenbergOpts = {
         threads?: number
  }