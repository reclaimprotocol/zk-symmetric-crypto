pragma circom 2.0.0;

include "./generics-bits.circom";

/**
 * Perform ChaCha Quarter Round
 * Assume 4 words of 32 bits each
 * Each word must be little endian
 */
template QR(BITS_PER_WORD) {
	signal input in[4][BITS_PER_WORD];
	signal output out[4][BITS_PER_WORD];

	var tmp[4][BITS_PER_WORD] = in;

	// a += b
	component add1 = AddBits(BITS_PER_WORD);
	add1.a <== tmp[0];
	add1.b <== tmp[1];

	tmp[0] = add1.out;

	// d ^= a
	component xor1 = XorBits(BITS_PER_WORD);
	xor1.a <== tmp[3];
	xor1.b <== tmp[0];
	tmp[3] = xor1.out;

	// d = RotateLeft32BitsUnsafe(d, 16)
	component rot1 = RotateLeftBits(BITS_PER_WORD, 16);
	rot1.in <== tmp[3];
	tmp[3] = rot1.out;

	// c += d
	component add2 = AddBits(BITS_PER_WORD);
	add2.a <== tmp[2];
	add2.b <== tmp[3];
	tmp[2] = add2.out;

	// b ^= c
	component xor2 = XorBits(BITS_PER_WORD);
	xor2.a <== tmp[1];
	xor2.b <== tmp[2];
	tmp[1] = xor2.out;

	// b = RotateLeft32BitsUnsafe(b, 12)
	component rot2 = RotateLeftBits(BITS_PER_WORD, 12);
	rot2.in <== tmp[1];
	tmp[1] = rot2.out;
	
	// a += b
	component add3 = AddBits(BITS_PER_WORD);
	add3.a <== tmp[0];
	add3.b <== tmp[1];
	tmp[0] = add3.out;

	// d ^= a
	component xor3 = XorBits(BITS_PER_WORD);
	xor3.a <== tmp[3];
	xor3.b <== tmp[0];
	tmp[3] = xor3.out;

	// d = RotateLeft32BitsUnsafe(d, 8)
	component rot3 = RotateLeftBits(BITS_PER_WORD, 8);
	rot3.in <== tmp[3];
	tmp[3] = rot3.out;

	// c += d
	component add4 = AddBits(BITS_PER_WORD);
	add4.a <== tmp[2];
	add4.b <== tmp[3];
	tmp[2] = add4.out;

	// b ^= c
	component xor4 = XorBits(BITS_PER_WORD);
	xor4.a <== tmp[1];
	xor4.b <== tmp[2];
	tmp[1] = xor4.out;

	// b = RotateLeft32BitsUnsafe(b, 7)
	component rot4 = RotateLeftBits(BITS_PER_WORD, 7);
	rot4.in <== tmp[1];
	tmp[1] = rot4.out;

	out <== tmp;
}