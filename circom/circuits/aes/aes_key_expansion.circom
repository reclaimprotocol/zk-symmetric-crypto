// Copyright © 2022, Electron Labs
pragma circom 2.0.0;

include "helper_functions.circom";
include "aes_emulation_tables.circom";

template AES_KEY_EXPAND(KEY_SIZE_BYTES) {
	var BITS_PER_WORD = 8;
	signal input key[KEY_SIZE_BYTES * BITS_PER_WORD]; 

	var rcon[10][BITS_PER_WORD] = [
		[0, 0, 0, 0, 0, 0, 0, 1], // 0x01
		[0, 0, 0, 0, 0, 0, 1, 0], // 0x02
		[0, 0, 0, 0, 0, 1, 0, 0], // 0x04
		[0, 0, 0, 0, 1, 0, 0, 0], // 0x08
		[0, 0, 0, 1, 0, 0, 0, 0], // 0x10
		[0, 0, 1, 0, 0, 0, 0, 0], // 0x20,
		[0, 1, 0, 0, 0, 0, 0, 0], // 0x40
		[1, 0, 0, 0, 0, 0, 0, 0], // 0x80
		[0, 0, 0, 1, 1, 0, 1, 1], // 0x1b
		[0, 0, 1, 1, 0, 1, 1, 0] // 0x36
	];

	var Nr = KEY_SIZE_BYTES == 32 ? 14 : (KEY_SIZE_BYTES == 24 ? 12 : 10);
	var Nb = 4;
	var Nk = KEY_SIZE_BYTES / 4;
	var ksWords = Nb * (Nr + 1);

	// output words, each word is 4 bytes
	var w[ksWords][4][BITS_PER_WORD];
	component bits2num_1[ksWords][4];
	component num2bits_1[ksWords][4];
	component xor1[ksWords][BITS_PER_WORD];
	component xor2[ksWords][4][BITS_PER_WORD];
	var temp[4][BITS_PER_WORD];
	var tmpWord[BITS_PER_WORD];

	signal output out[ksWords * 4 * BITS_PER_WORD];

	// set the first Nk words to the key
	for (var i = 0; i < Nk; i++) {
		for(var j = 0; j < 4; j++) {
			for(var k = 0; k < BITS_PER_WORD; k++) {
				w[i][j][k] = key[((i * 4) + j)*BITS_PER_WORD + k];
			}
		}
	}

	// expand the key into the remainder of the schedule
	for (var i=Nk; i<(Nb*(Nr+1)); i++) {
		for(var j = 0; j < 4; j++) {
			temp[j] = w[i-1][j];
		}

		if(i % Nk == 0) {
			// rotate word
			tmpWord = temp[0];
			temp[0] = temp[1];
			temp[1] = temp[2];
			temp[2] = temp[3];
			temp[3] = tmpWord;
		}
		
		if(
			i % Nk == 0
			// 256-bit key has subWord applied every 4th word
			|| (KEY_SIZE_BYTES == 32 && i%Nk == 4)
		) {
			for(var j = 0; j < 4; j++) {
				// sbox substitution for each word
				bits2num_1[i][j] = Bits2Num(BITS_PER_WORD);
				for(var k = 0; k < BITS_PER_WORD; k++) {
					bits2num_1[i][j].in[k] <== temp[j][BITS_PER_WORD - k - 1];
				}
				num2bits_1[i][j] = Num2Bits(8);
				num2bits_1[i][j].in <-- emulated_aesenc_rijndael_sbox(bits2num_1[i][j].out);

				for(var k = 0; k < BITS_PER_WORD; k++) {
					temp[j][k] = num2bits_1[i][j].out[BITS_PER_WORD - k - 1];
				}
			}
		}

		if(i % Nk == 0) {
			// xor first word with rcon
			for(var k = 0; k < BITS_PER_WORD; k++) {
				xor1[i][k] = XOR();
				xor1[i][k].a <== temp[0][k];
				xor1[i][k].b <== rcon[i/Nk - 1][k];
				temp[0][k] = xor1[i][k].out;
			}
		}

		// w[i] = w[i-1] and w[i-Nk]
		for(var j = 0; j < 4; j++) {
			for(var k = 0; k < BITS_PER_WORD; k++) {
				xor2[i][j][k] = XOR();
				xor2[i][j][k].a <== temp[j][k];
				xor2[i][j][k].b <== w[i-Nk][j][k];
				w[i][j][k] = xor2[i][j][k].out;
			}
		}
	}

	// finally, set out to the expanded key
	for (var i = 0; i < Nb*(Nr+1); i++) {
		for (var j = 0; j < 4; j++) {
			for(var k = 0; k < BITS_PER_WORD; k++) {
				out[(i*4 + j)*BITS_PER_WORD + k] <== w[i][j][k];
			}
		}
	}
}