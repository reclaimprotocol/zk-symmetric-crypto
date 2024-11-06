pragma circom 2.0.0;

include "../chacha20/generics-bits.circom";

/**
* Rotate in all directions required by
* the ChaCha20 cipher
*/
template _RotateLeft32Bits(BITS) {
	signal input in[BITS];
	signal output out[4][BITS];

	component rotl1 = RotateLeftBits(BITS, 16);
	rotl1.in <== in;
	out[0] <== rotl1.out;

	component rotl2 = RotateLeftBits(BITS, 12);
	rotl2.in <== in;
	out[1] <== rotl2.out;

	component rotl3 = RotateLeftBits(BITS, 8);
	rotl3.in <== in;
	out[2] <== rotl3.out;

	component rotl4 = RotateLeftBits(BITS, 7);
	rotl4.in <== in;
	out[3] <== rotl4.out;
}

component main = _RotateLeft32Bits(32);