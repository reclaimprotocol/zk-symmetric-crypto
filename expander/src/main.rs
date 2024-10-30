mod lib;

use lib::{load_circuit, load_solver, prove, SymmetricCryptoAlgorithm};
// use peak_alloc::PeakAlloc;
use std::{fs, time::Instant};

//#[global_allocator]
//static PEAK_ALLOC: PeakAlloc = PeakAlloc;

fn main() {
    prove_circuit_file_inner(
        "../resources/expander/chacha20.txt",
        "../resources/expander/chacha20-solver.txt",
    );
    println!("Hello, world!");
}

fn prove_circuit_file_inner(
    circuit_filename: &str,
    solver_filename: &str,
) {
    let circuit_bytes = fs::read(circuit_filename).unwrap();
    let solver_bytes = fs::read(solver_filename).unwrap();
    let pub_bytes = fs::read("../resources/expander/pub.txt").unwrap();
    let priv_bytes = fs::read("../resources/expander/priv.txt").unwrap();
   
    load_circuit(SymmetricCryptoAlgorithm::ChaCha20, circuit_bytes.clone());
    load_solver(SymmetricCryptoAlgorithm::ChaCha20, solver_bytes.clone());
    //solver.solve_witness_from_raw_inputs(vars, public_vars);
    println!("yay done");
    // let wtns = Witness::deserialize_from(&witness_bytes[..]).unwrap();
    //let proof_bytes = fs::read("./pkg/proof.txt").unwrap();
    
    let now = Instant::now();
    // let verified = verify(SymmetricCryptoAlgorithm::ChaCha20, witness_bytes, proof_bytes);
    // println!("Verified: {}", verified);
    for _ in 0..10 {
        prove(SymmetricCryptoAlgorithm::ChaCha20, priv_bytes.clone(), pub_bytes.clone());
    }
    
    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);
    //let current_mem = PEAK_ALLOC.peak_usage_as_mb();
	//println!("This program max used {} MB of RAM.", current_mem);
    // let mut bytes = Vec::new();

    // proof.(&mut bytes)?;
    // claimed_v.serialize_into(&mut bytes)?;

    // Ok(bytes);
}