pragma circom 2.0.0;

include "../aes/aes_ctr.circom";

component main = AES_CTR(16 * 8, 32);