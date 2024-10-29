
export type Proof = {
	/** serialised SnarkJS proof */
	proofJson: string

	plaintext: Uint8Array
}

export type VerificationKey = {
	/** binary data for .zkey file */
	data: Uint8Array
	json?: any
}

export type Redaction = {
	startIndex: number
	endIndex: number
}

export type PrivateInput = {
	/** AES-256-CTR key to decrypt ciphertext */
	key: Uint8Array
	/** IV for the ciphertext decryption */
	iv: Uint8Array
}

export type PublicInput = {
	/** the ciphertext to decrypt */
	ciphertext: Uint8Array
	/** the redacted plaintext */
	//redactedPlaintext: Uint8Array
}