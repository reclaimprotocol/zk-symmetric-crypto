use std::{io::Cursor, panic, sync::Mutex};

use expander_arith::{Field, FieldSerde, FieldSerdeError};
use expander_circuit::{Circuit, FromEccSerde, RecursiveCircuit};
use expander_config::{BN254ConfigKeccak, Config, GKRConfig, GKRScheme, MPIConfig};
use expander_gkr::{Prover, Verifier};
use expander_transcript::Proof;
use wasm_bindgen::prelude::*;

extern crate web_sys;
extern crate console_error_panic_hook;

type _ZKMode = BN254ConfigKeccak;
type _Circuit = Circuit<_ZKMode>;
type ProofData = Vec<u8>;

#[derive(Clone, Copy, Debug)]
#[wasm_bindgen]
pub enum SymmetricCryptoAlgorithm {
	ChaCha20 = 0,
}

#[derive(Debug)]
pub enum Error {
	AlgorithmNotLoaded(SymmetricCryptoAlgorithm),
}

static GLOBAL_ALGS: Mutex<Vec<Option<_Circuit>>> = Mutex::new(Vec::new());

#[wasm_bindgen]
pub fn load_circuit(
	alg: SymmetricCryptoAlgorithm,
	circuit_bytes: Vec<u8>,
) {
	prep();

	let cursor = Cursor::new(circuit_bytes);
	let rc = RecursiveCircuit::deserialize_from(cursor);
	let circuit = rc.flatten();
	set_circuit(alg, circuit);
}

#[wasm_bindgen]
pub fn prove(alg: SymmetricCryptoAlgorithm, witness_bytes: Vec<u8>) -> ProofData {
	prep();

	let mut circuit = get_circuit_with_witness(alg, witness_bytes)
		.unwrap();

	let mut prover = Prover::new(&get_config());
	prover.prepare_mem(&circuit);

	let mut arr =Vec::new();
	for item in circuit.public_input.iter() {
		item.serialize_into(&mut arr).unwrap();
	}

	println!("Public input: {:?}", arr.len());

	let (claimed_v, proof) = prover.prove(&mut circuit);
	return dump_proof_and_claimed_v(&proof, &claimed_v).unwrap();
}

#[wasm_bindgen]
pub fn verify(
	alg: SymmetricCryptoAlgorithm,
	public_input_bytes: Vec<u8>,
	proof_data: ProofData
) -> bool {
	prep();

	let mut circuit: Circuit<BN254ConfigKeccak> = get_circuit(alg).unwrap();

	// let wtns_cursor = Cursor::new(witness_bytes);
	// let mut wtns: Witness<BN254ConfigKeccak> = Witness::deserialize_from(wtns_cursor);
	let mut pub_inputs = Vec::new();
	let mut pub_input_cursor = Cursor::new(public_input_bytes);
	while let Ok(value) = <_ZKMode as GKRConfig>::CircuitField::deserialize_from(&mut pub_input_cursor) {
		pub_inputs.push(value);
	}

	circuit.set_random_input_for_test();
	circuit.public_input = pub_inputs;
	circuit.evaluate();

	let public_input = circuit.public_input.clone();
	let verifier = Verifier::new(&get_config());
	let (proof, claimed_v) = load_proof_and_claimed_v(&proof_data)
		.unwrap();
	return verifier.verify(&mut circuit, &public_input, &claimed_v, &proof);
}

pub fn get_circuit_with_witness(alg: SymmetricCryptoAlgorithm, witness_bytes: Vec<u8>) -> Result<_Circuit, Error> {
	let mut circuit = get_circuit(alg).unwrap();
    circuit.load_witness_bytes(&witness_bytes, false);
    circuit.evaluate();

	return Ok(circuit);
}

fn set_circuit(alg: SymmetricCryptoAlgorithm, circuit: _Circuit) {
	let mut algs = GLOBAL_ALGS.lock().unwrap();
	let alg_value = alg as usize;
	// append to array till we reach the index
	while algs.len() <= alg_value {
		algs.push(None);
	}

	algs[alg_value] = Some(circuit);
}

/**
 * Retrieve clone of the circuit for the given algorithm,
 * or return an error if the algorithm is not supported.
 */
fn get_circuit(alg: SymmetricCryptoAlgorithm) -> Result<_Circuit, Error> {
	let algs = GLOBAL_ALGS.lock().unwrap();
	let alg_value = alg as usize;
	if algs.len() <= alg_value {
		return Err(Error::AlgorithmNotLoaded(alg));
	}

	let circuit_opt = algs[alg_value].clone();
	return circuit_opt.ok_or(Error::AlgorithmNotLoaded(alg));
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