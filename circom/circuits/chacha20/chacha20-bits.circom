pragma circom 2.0.0;

include "./chacha-round.circom";
include "./chacha-qr.circom";
include "./generics-bits.circom";

/** ChaCha20 in counter mode */
// BITS_PER_WORD = 32
template ChaCha20(N, BITS_PER_WORD) {
	// key => 8 32-bit words = 32 bytes
	signal input key[8][BITS_PER_WORD];
	// nonce => 3 32-bit words = 12 bytes
	signal input nonce[3][BITS_PER_WORD];
	// counter => 32-bit word to apply w nonce
	signal input counter[BITS_PER_WORD];
	// in => N 32-bit words => N 4 byte words
	signal input in[N][BITS_PER_WORD];
	// out => N 32-bit words => N 4 byte words
	signal output out[N][BITS_PER_WORD];

	var tmp[16][BITS_PER_WORD] = [
		[
			// 0x61707865
			0, 1, 1, 0, 0, 0, 0, 1, 0,
			1, 1, 1, 0, 0, 0, 0, 0, 1,
			1, 1, 1, 0, 0, 0, 0, 1, 1,
			0, 0, 1, 0, 1
		],
		[
			// 0x3320646e
			0, 0, 1, 1, 0, 0, 1, 1, 0,
			0, 1, 0, 0, 0, 0, 0, 0, 1,
			1, 0, 0, 1, 0, 0, 0, 1, 1,
			0, 1, 1, 1, 0
		],
		[
			// 0x79622d32
			0, 1, 1, 1, 1, 0, 0, 1, 0,
			1, 1, 0, 0, 0, 1, 0, 0, 0,
			1, 0, 1, 1, 0, 1, 0, 0, 1,
			1, 0, 0, 1, 0
		],
		[
			// 0x6b206574
			0, 1, 1, 0, 1, 0, 1, 1, 0,
			0, 1, 0, 0, 0, 0, 0, 0, 1,
			1, 0, 0, 1, 0, 1, 0, 1, 1,
			1, 0, 1, 0, 0
		],
		key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
		counter,
		nonce[0], nonce[1], nonce[2]
	];
	var i = 0;
	var j = 0;

	// do the ChaCha20 rounds
	component rounds[N/16];
	component xors[N];
	for(i = 0; i < N/16; i++) {
		rounds[i] = Round(BITS_PER_WORD);
		rounds[i].in <== tmp;
		// XOR block with input
		for(j = 0; j < 16; j++) {
			xors[i*16 + j] = XorBits(BITS_PER_WORD);
			xors[i*16 + j].a <== in[i*16 + j];
			xors[i*16 + j].b <== rounds[i].out[j];
			out[i*16 + j] <== xors[i*16 + j].out;
		}
		// increment the counter
		// TODO: we only use one block
		// at a time, so isn't required
		// tmp[12] = tmp[12] + 1;
	}
}