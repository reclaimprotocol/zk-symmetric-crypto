pragma circom 2.0.0;

include "aes_ctr.circom";

/**
 * Does AES-CTR decryption, with the key, nonce & counter
 *
 * This circuit takes in the encryption keys &
 * an N byte AES-CTR ciphertext and verifies that
 * it decrypts to some plaintext
 * BITS_PER_WORD = 8
 */	
template AES_NONCE_CTR(N, KEY_SIZE_BYTES) {
	var BITS_PER_WORD = 8;
	// the key, iv & startCounter are private inputs
	// they must be specified by the client 
	signal input key[KEY_SIZE_BYTES * BITS_PER_WORD];
	signal input nonce[12 * BITS_PER_WORD];
	signal input counter[4 * BITS_PER_WORD];
	// the ciphertext is public input
	// so the witness can check the right data was sent to the circuit
	signal input in[N*8];
	signal output out[N*8];

	component cipher = AES_CTR(N * BITS_PER_WORD, KEY_SIZE_BYTES);
	cipher.in <== in;
	cipher.key <== key;

	// set counter
	for(var i = 0; i < 12 * BITS_PER_WORD; i++) {
		cipher.ctr[i] <== nonce[i];
	}
	for(var i = 0; i < 4 * BITS_PER_WORD; i++) {
		cipher.ctr[i + 12*BITS_PER_WORD] <== counter[i];
	}

    out <== cipher.out;
}