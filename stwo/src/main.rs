#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

pub mod aes;
pub mod chacha;

fn main() {
    println!("s2circuits - Stwo ChaCha/AES circuits");

    // Quick sanity check
    let mut state = [0x11111111u32, 0x01020304, 0x9b8d6f43, 0x01234567];
    println!("Before quarter-round: {:08x?}", state);

    chacha::quarter_round::quarter_round_native(&mut state);
    println!("After quarter-round:  {:08x?}", state);

    // Expected from RFC 7539
    let expected = [0xea2a92f4u32, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb];
    assert_eq!(state, expected, "Quarter-round test failed!");
    println!("Quarter-round test passed!");
}
