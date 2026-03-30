#![feature(portable_simd)]
#![feature(iter_array_chunks)]
#![feature(array_chunks)]

pub mod aes;
pub mod chacha;

#[cfg(target_arch = "wasm32")]
pub mod wasm_api;
