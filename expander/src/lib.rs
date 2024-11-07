use std::{io::Cursor, panic};

use expander_arith::{Field, FieldSerde, FieldSerdeError};
use expander_circuit::{Circuit, FromEccSerde, RecursiveCircuit};
use expander_compiler::{frontend::{BN254Config, WitnessSolver}, utils::serde::Serde};
use expander_config::{BN254ConfigKeccak, Config, GKRConfig, GKRScheme, MPIConfig};
use expander_gkr::{Prover, Verifier};
use expander_transcript::Proof;
use wasm_bindgen::prelude::*;

extern crate web_sys;
extern crate console_error_panic_hook;

type _ZKMode = BN254ConfigKeccak;
type _Circuit = Circuit<_ZKMode>;
type _WitnessSolver = WitnessSolver<BN254Config>;
type ProofData = Vec<u8>;

#[derive(Clone, Copy, Debug)]
#[wasm_bindgen]
pub enum SymmetricCryptoAlgorithm {
	ChaCha20 = 0,
}

#[derive(Debug)]
pub enum Error {
	CircuitNotLoaded(SymmetricCryptoAlgorithm),
	SolverNotLoaded(SymmetricCryptoAlgorithm),
}

static mut CIRCUITS: Vec<Option<_Circuit>> = Vec::new();
static mut SOLVERS: Vec<Option<&'static _WitnessSolver>> = Vec::new();

#[wasm_bindgen]
pub fn load_circuit(alg: SymmetricCryptoAlgorithm, bytes: Vec<u8>) {
	prep();

	let cursor = Cursor::new(bytes);
	let rc = RecursiveCircuit::deserialize_from(cursor);
	let circuit = rc.flatten();

	set_circuit(alg, circuit);
}

#[wasm_bindgen]
pub fn load_solver(
	alg: SymmetricCryptoAlgorithm,
	bytes: Vec<u8>,
) {
	prep();

	let cursor = Cursor::new(bytes);
	let solver = <_WitnessSolver as expander_compiler::utils::serde::Serde>
		::deserialize_from(cursor).unwrap();
	let solver_static: &'static _WitnessSolver = Box::leak(Box::new(solver));

	set_solver(alg, solver_static);
}

#[wasm_bindgen]
pub fn is_circuit_loaded(alg: SymmetricCryptoAlgorithm) -> bool {
	prep();
	return get_circuit(alg).is_ok();
}

#[wasm_bindgen]
pub fn is_solver_loaded(alg: SymmetricCryptoAlgorithm) -> bool {
	prep();
	return get_solver(alg).is_ok();
}

#[wasm_bindgen]
pub fn prove(
	alg: SymmetricCryptoAlgorithm,
	priv_input_bits: Vec<u8>,
	pub_input_bits: Vec<u8>,
) -> ProofData {
	prep();

	let solver = get_solver(alg).unwrap();
	let wtns = solver.solve_witness_from_raw_inputs(
		map_to_circuit_fields(&priv_input_bits),
		map_to_circuit_fields(&pub_input_bits),
	).unwrap();

	let mut wtns_serialised = Vec::new();
	wtns.serialize_into(&mut wtns_serialised).unwrap();
	
	let mut circuit = get_circuit(alg).unwrap();
	circuit.load_witness_bytes(&wtns_serialised, false);

	let mut prover = Prover::new(&get_config());
	prover.prepare_mem(&circuit);

	let (claimed_v, proof) = prover.prove(&mut circuit);

	return dump_proof_and_claimed_v(&proof, &claimed_v).unwrap();
}

#[wasm_bindgen]
pub fn verify(
	alg: SymmetricCryptoAlgorithm,
	pub_input_bits: Vec<u8>,
	proof_data: ProofData
) -> bool {
	prep();

	let mut circuit: Circuit<BN254ConfigKeccak> = get_circuit(alg).unwrap();

	circuit.set_random_input_for_test();
	circuit.public_input = map_to_circuit_fields(&pub_input_bits);
	circuit.evaluate();

	let public_input = circuit.public_input.clone();
	let verifier = Verifier::new(&get_config());
	let (proof, claimed_v) = load_proof_and_claimed_v(&proof_data)
		.unwrap();
	return verifier.verify(&mut circuit, &public_input, &claimed_v, &proof);
}

fn set_circuit(alg: SymmetricCryptoAlgorithm, circuit: _Circuit) {
	let alg_value = alg as usize;
	unsafe {
		// append to array till we reach the index
		while CIRCUITS.len() <= alg_value {
			CIRCUITS.push(None);
		}

		CIRCUITS[alg_value] = Some(circuit);
	}
}

/**
 * Retrieve clone of the circuit for the given algorithm,
 * or return an error if the algorithm is not supported.
 */
fn get_circuit(alg: SymmetricCryptoAlgorithm) -> Result<_Circuit, Error> {
	let alg_value = alg as usize;
	unsafe {
		if CIRCUITS.len() <= alg_value {
			return Err(Error::CircuitNotLoaded(alg));
		}
	
		let circuit_opt = CIRCUITS[alg_value].clone();
		return circuit_opt.ok_or(Error::CircuitNotLoaded(alg));
	}
}


fn set_solver(alg: SymmetricCryptoAlgorithm, value: &'static _WitnessSolver) {
	let alg_value = alg as usize;
	unsafe {
		// append to array till we reach the index
		while SOLVERS.len() <= alg_value {
			SOLVERS.push(None);
		}

		SOLVERS[alg_value] = Some(value);
	}
}

/**
 * Retrieve clone of the circuit for the given algorithm,
 * or return an error if the algorithm is not supported.
 */
fn get_solver(alg: SymmetricCryptoAlgorithm) -> Result<&'static _WitnessSolver, Error> {
	let alg_value = alg as usize;
	unsafe {
		if SOLVERS.len() <= alg_value {
			return Err(Error::SolverNotLoaded(alg));
		}
	
		return SOLVERS[alg_value].ok_or(Error::SolverNotLoaded(alg));
	}
}

fn get_config() -> Config<_ZKMode> {
	let mpi_config = MPIConfig::new();
	let config = Config::<_ZKMode>::new(GKRScheme::Vanilla, mpi_config.clone());
	return config
}

fn prep() {
	panic::set_hook(Box::new(console_error_panic_hook::hook));
}

fn dump_proof_and_claimed_v<F: Field + FieldSerde>(
    proof: &Proof,
    claimed_v: &F,
) -> Result<Vec<u8>, FieldSerdeError> {
    let mut bytes = Vec::new();

    proof.serialize_into(&mut bytes)?;
    claimed_v.serialize_into(&mut bytes)?;

    Ok(bytes)
}

fn load_proof_and_claimed_v<F: Field + FieldSerde>(
    bytes: &[u8],
) -> Result<(Proof, F), FieldSerdeError> {
    let mut cursor = Cursor::new(bytes);

    let proof = Proof::deserialize_from(&mut cursor)?;
    let claimed_v = F::deserialize_from(&mut cursor)?;

    Ok((proof, claimed_v))
}

fn map_to_circuit_fields(arr: &[u8]) -> Vec<<BN254ConfigKeccak as GKRConfig>::CircuitField> {
	let mut pub_inputs = Vec::new();
	let sample = [0u8; 32];

	for byte in arr {
		let mut sample_mut = sample.clone();
		sample_mut[0] = *byte;
		let value = <BN254ConfigKeccak as GKRConfig>::CircuitField::from_uniform_bytes(&sample_mut);
		pub_inputs.push(value);
	}

	return pub_inputs;
}