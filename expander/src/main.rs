mod lib;

use lib::{load_circuit, verify, prove, SymmetricCryptoAlgorithm};
use peak_alloc::PeakAlloc;
use std::{fs, time::Instant};

#[global_allocator]
static PEAK_ALLOC: PeakAlloc = PeakAlloc;

fn main() {
    prove_circuit_file_inner(
        "../bench/circuit.txt",
        "../bench/witness.txt",
    );
    println!("Hello, world!");
}

fn prove_circuit_file_inner(
    circuit_filename: &str,
    witness_filename: &str,
) {
    let circuit_bytes = fs::read(circuit_filename).unwrap();
    let witness_bytes = fs::read(witness_filename).unwrap();
    let proof_bytes = fs::read("./pkg/proof.txt").unwrap();
    load_circuit(SymmetricCryptoAlgorithm::ChaCha20, circuit_bytes);

    let now = Instant::now();
    // let verified = verify(SymmetricCryptoAlgorithm::ChaCha20, witness_bytes, proof_bytes);
    // println!("Verified: {}", verified);
    for _ in 0..10 {
    prove(SymmetricCryptoAlgorithm::ChaCha20, witness_bytes.clone());
    }
    
    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);
    let current_mem = PEAK_ALLOC.peak_usage_as_mb();
	println!("This program max used {} MB of RAM.", current_mem);
    // let mut bytes = Vec::new();

    // proof.(&mut bytes)?;
    // claimed_v.serialize_into(&mut bytes)?;

    // Ok(bytes);
}