pragma circom 2.0.0;

include "./chacha-qr.circom";
include "./generics-bits.circom";

template Round(BITS_PER_WORD) {
	// in => 16 32-bit words
	signal input in[16][BITS_PER_WORD];
	// out => 16 32-bit words
	signal output out[16][BITS_PER_WORD];

	var tmp[16][BITS_PER_WORD] = in;

	component rounds[10 * 8];
	component finalAdd[16];
	// i-th round
	var i = 0;
	// col loop counter
	var j = 0;
	// counter for the rounds array
	var k = 0;
	for(i = 0; i < 10; i++) {
		// columns of the matrix in a loop
		// 0, 4, 8, 12
		// 1, 5, 9, 13
		// 2, 6, 10, 14
		// 3, 7, 11, 15
		for(j = 0; j < 4; j++) {
			rounds[k] = QR(BITS_PER_WORD);
			rounds[k].in[0] <== tmp[j];
			rounds[k].in[1] <== tmp[j + 4];
			rounds[k].in[2] <== tmp[j + 8];
			rounds[k].in[3] <== tmp[j + 12];

			tmp[j] = rounds[k].out[0];
			tmp[j + 4] = rounds[k].out[1];
			tmp[j + 8] = rounds[k].out[2];
			tmp[j + 12] = rounds[k].out[3];

			k ++;
		}

		// 4 diagnals
		// 0, 5, 10, 15
		rounds[k] = QR(BITS_PER_WORD);
		rounds[k].in[0] <== tmp[0];
		rounds[k].in[1] <== tmp[5];
		rounds[k].in[2] <== tmp[10];
		rounds[k].in[3] <== tmp[15];

		tmp[0] = rounds[k].out[0];
		tmp[5] = rounds[k].out[1];
		tmp[10] = rounds[k].out[2];
		tmp[15] = rounds[k].out[3];

		k ++;

		// 1, 6, 11, 12
		rounds[k] = QR(BITS_PER_WORD);
		rounds[k].in[0] <== tmp[1];
		rounds[k].in[1] <== tmp[6];
		rounds[k].in[2] <== tmp[11];
		rounds[k].in[3] <== tmp[12];

		tmp[1] = rounds[k].out[0];
		tmp[6] = rounds[k].out[1];
		tmp[11] = rounds[k].out[2];
		tmp[12] = rounds[k].out[3];

		k ++;

		// 2, 7, 8, 13
		rounds[k] = QR(BITS_PER_WORD);
		rounds[k].in[0] <== tmp[2];
		rounds[k].in[1] <== tmp[7];
		rounds[k].in[2] <== tmp[8];
		rounds[k].in[3] <== tmp[13];

		tmp[2] = rounds[k].out[0];
		tmp[7] = rounds[k].out[1];
		tmp[8] = rounds[k].out[2];
		tmp[13] = rounds[k].out[3];

		k ++;

		// 3, 4, 9, 14
		rounds[k] = QR(BITS_PER_WORD);
		rounds[k].in[0] <== tmp[3];
		rounds[k].in[1] <== tmp[4];
		rounds[k].in[2] <== tmp[9];
		rounds[k].in[3] <== tmp[14];

		tmp[3] = rounds[k].out[0];
		tmp[4] = rounds[k].out[1];
		tmp[9] = rounds[k].out[2];
		tmp[14] = rounds[k].out[3];

		k ++;
	}

	// add the result to the input
	for(i = 0; i < 16; i++) {
		finalAdd[i] = AddBits(BITS_PER_WORD);
		finalAdd[i].a <== tmp[i];
		finalAdd[i].b <== in[i];
		tmp[i] = finalAdd[i].out;
	}

	out <== tmp;
}
