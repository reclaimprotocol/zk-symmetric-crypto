// Copyright © 2022, Electron Labs
pragma circom 2.0.0;

include "aes_emulation_tables.circom";
include "aes_emulation.circom";
include "helper_functions.circom";

// Keystream 을 만들어 내는 컴포넌트
// in: ctr
// ks: key
// out = AES(ctr, key)
template AESEncrypt(ROUNDS)
{
    // (rounds + 1) * word_size * bytes_in_word * bits_in_byte
    var keySize = (ROUNDS + 1) * 4 * 4 * 8;
    signal input in[128];
    signal input ks[keySize];
    signal output out[128];

    var ks_index = 0;
    var s[4][32], t[4][32];
    
    var i,j,k,l,m;
    
    component xor_1[4][32];

    // 1. AddRoundKey
    for(i=0; i<4; i++)
    {
        for(j=0; j<32; j++)
        {
            xor_1[i][j] = XOR();
            xor_1[i][j].a <== in[i*32+j];
            xor_1[i][j].b <== ks[(i+ks_index)*32+j];

            s[i][j] = xor_1[i][j].out;
        }
    }
    
    ks_index += 4;

    component xor_2[ROUNDS - 1][4][3][32];
    component bits2num_1[ROUNDS - 1][4][4];
    component num2bits_1[ROUNDS - 1][4][4];
    component xor_3[ROUNDS - 1][4][32];

    // 2. T-Table 기반 최적화
    //   j=0 (첫 번째 열)일 때:
    //   k=0: T₀[s₀] 저장
    //   k=1: T₀[s₀] ⊕ T₁[s₁] 계산
    //   k=2: (T₀[s₀] ⊕ T₁[s₁]) ⊕ T₂[s₂] 계산
    //   k=3: ((T₀[s₀] ⊕ T₁[s₁]) ⊕ T₂[s₂]) ⊕ T₃[s₃] = MixColumns 결과
    for(i=0; i<ROUNDS-1; i++)
    {
        for(j=0; j<4; j++)
        {
            for(k=0; k<4; k++)
            {
                bits2num_1[i][j][k] = Bits2Num(8);
                num2bits_1[i][j][k] = Num2Bits(32);
                // 2.1 ShiftRows
                var s_tmp[32] = s[(j+k)%4];
                
                for(l=0; l<8; l++) bits2num_1[i][j][k].in[l] <== s_tmp[k*8+7-l];

                // 2.2 SubBytes + MixColumns : T-table 조회로 대체
                num2bits_1[i][j][k].in <-- emulated_aesenc_enc_table(k, bits2num_1[i][j][k].out);
                // in에 들어있는건 0x64d5d5b1 처럼 concat되어있는것. 그러므로 이를 각각 잘라서 xor 해줘야지 Multiplication이 완료된다.

                // 2.3 열 결합
                if(k==0)
                {
                    for(l=0; l<4; l++)
                    {
                        for(m=0; m<8; m++)
                        {
                            xor_2[i][j][k][l*8+m] = XOR();
                            xor_2[i][j][k][l*8+m].a <== num2bits_1[i][j][k].out[l*8+7-m];
                        }
                    }
                }
                else if(k<3)
                {
                    for(l=0; l<4; l++)
                    {
                        for(m=0; m<8; m++)
                        {
                            xor_2[i][j][k-1][l*8+m].b <== num2bits_1[i][j][k].out[l*8+7-m];

                            xor_2[i][j][k][l*8+m] = XOR();
                            xor_2[i][j][k][l*8+m].a <== xor_2[i][j][k-1][l*8+m].out;
                        }
                    }
                }
                else
                {
                    for(l=0; l<4; l++)
                    {
                        for(m=0; m<8; m++)
                        {
                            xor_2[i][j][k-1][l*8+m].b <== num2bits_1[i][j][k].out[l*8+7-m];

                            xor_3[i][j][l*8+m] = XOR();
                            xor_3[i][j][l*8+m].a <== xor_2[i][j][k-1][l*8+m].out;
                        }
                    }
                }
            }
        }

        // 2.4 AddRoundKey
        for(j=0; j<4; j++)
        {
            for(l=0; l<32; l++)
            {
                xor_3[i][j][l].b <== ks[(j+ks_index)*32+l];
                s[j][l] = xor_3[i][j][l].out;
            }
        }
        ks_index += 4;
    }

    // 3. 마지막 라운드
    // SubBytpes + ShiftRows + AddRoundKey
    component bits2num_2[16];
    var s_bytes[16];

    for(i=0; i<4; i++)
    {
        for(j=0; j<4; j++)
        {
            bits2num_2[i*4+j] = Bits2Num(8);
            for(k=0; k<8; k++) bits2num_2[i*4+j].in[k] <== s[i][j*8+7-k];
            s_bytes[i*4+j] = bits2num_2[i*4+j].out;
        }
    }

    component row_shifting = EmulatedAesencRowShifting();
    component sub_bytes = EmulatedAesencSubstituteBytes();
    // 3.1 Shift Rows
    for(i=0; i<16; i++) row_shifting.in[i] <== s_bytes[i];
    // 3.2 SubBytes
    for(i=0; i<16; i++) sub_bytes.in[i] <== row_shifting.out[i];

    component num2bits_2[16];

    for(i=0; i<4; i++)
    {
        for(j=0; j<4; j++)
        {
            num2bits_2[i*4+j] = Num2Bits(8);
            num2bits_2[i*4+j].in <== sub_bytes.out[i*4+j];
            for(k=0; k<8; k++) s[i][j*8+k] = num2bits_2[i*4+j].out[7-k];
        }
    }

    component xor_4[4][32];

    // 3.3 AddRoundKey
    for(i=0; i<4; i++)
    {
        for(j=0; j<32; j++)
        {
            xor_4[i][j] = XOR();
            xor_4[i][j].a <== s[i][j];
            xor_4[i][j].b <== ks[(i+ks_index)*32+j];

            s[i][j] = xor_4[i][j].out;
        }
    }

    for(i=0; i<4; i++)
    {
        for(j=0; j<32; j++) out[i*32+j] <== s[i][j];
    }
}


