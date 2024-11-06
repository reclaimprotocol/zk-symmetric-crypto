// Copyright © 2022, Electron Labs
pragma circom 2.0.0;

include "aes_encrypt.circom";
include "helper_functions.circom";
include "aes_key_expansion.circom";

template AES_CTR(n_bits, KEY_SIZE_BYTES)
{
    var AES_ROUNDS = KEY_SIZE_BYTES == 32 ? 14 : (KEY_SIZE_BYTES == 24 ? 12 : 10);
    var msg_len = n_bits/8;
    signal input in[n_bits];
    signal input ctr[128];
    signal input key[KEY_SIZE_BYTES * 8];
    signal output out[n_bits];

    var EK[128];
    var p_index = 0, c_index = 0;
    var ctr_t[128] = ctr;
    var out_t[msg_len][8];

	component ke = AES_KEY_EXPAND(KEY_SIZE_BYTES);
	ke.key <== key;

    var i, j, k, l;

    component aes_encrypt_1[msg_len/16];
    component xor_1[msg_len/16][4][4][32];
    component num2bits_1[msg_len/16];
    component bits2num_1[msg_len/16];

    for(i=0; i<msg_len/16; i++)
    {
        aes_encrypt_1[i] = AESEncrypt(AES_ROUNDS);
        aes_encrypt_1[i].in <== ctr_t;
        aes_encrypt_1[i].ks <== ke.out;

        EK = aes_encrypt_1[i].out;

        for(j=0; j<4; j++)
        {
            for(k=0; k<4; k++)
            {
                for(l=0; l<8; l++)
                {
                    xor_1[i][j][k][l] = XOR();
                    xor_1[i][j][k][l].a <== in[i*128+j*32+k*8+l];
                    xor_1[i][j][k][l].b <== EK[j*32+k*8+l];

                    out[i*128+j*32+k*8+l] <== xor_1[i][j][k][l].out;
                }
            }
        }
        bits2num_1[i] = Bits2Num(32);
        num2bits_1[i] = Num2Bits(32);
        for(j=0; j<4; j++) 
        {
            for(k=0; k<8; k++) bits2num_1[i].in[j*8+k] <== ctr_t[(15-j)*8+7-k];
        }
        num2bits_1[i].in <== bits2num_1[i].out + 1;
        for(j=0; j<4; j++)
        {
            for(k=0; k<8; k++) ctr_t[((15-j)*8)+k] = num2bits_1[i].out[j*8+7-k];
        }
    }
}
