//! AIR for TOPRF verification circuit.
//!
//! Provides prove_toprf() and verify_toprf() functions for generating and
//! verifying STARK proofs of correct TOPRF computation.

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::{verify, VerificationError};
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{prove, CommitmentSchemeProver, ComponentProver};
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval, InfoEvaluator, TraceLocationAllocator};

use super::constraints::TOPRFEvalAtRow;
use super::gen::TOPRFTraceGen;
use super::{TOPRFInputs, TOPRFPublicInputs};
use crate::babyjub::field256::gen::BigInt256;

/// Component type for TOPRF verification.
pub type TOPRFComponent = FrameworkComponent<TOPRFEval>;

/// Evaluator for TOPRF verification constraints.
pub struct TOPRFEval {
    pub log_size: u32,
    pub claimed_sum: SecureField,
}

impl FrameworkEval for TOPRFEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: stwo_constraint_framework::EvalAtRow>(&self, eval: E) -> E {
        TOPRFEvalAtRow { eval }.eval()
    }
}

/// Get component info for TOPRF verification.
pub fn toprf_info() -> InfoEvaluator {
    let component = TOPRFEval {
        log_size: 10,
        claimed_sum: SecureField::zero(),
    };
    component.evaluate(InfoEvaluator::empty())
}

/// Public inputs for TOPRF proof - cryptographically bound via Fiat-Shamir.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOPRFProofPublicInputs {
    /// Domain separator (as bytes for serialization).
    pub domain_separator: Vec<u8>,

    /// Expected output hash (as bytes).
    pub output: Vec<u8>,

    /// Response points (x, y as bytes each).
    pub responses: Vec<(Vec<u8>, Vec<u8>)>,

    /// Share public keys (x, y as bytes each).
    pub share_public_keys: Vec<(Vec<u8>, Vec<u8>)>,

    /// DLEQ challenges.
    pub c: Vec<Vec<u8>>,

    /// DLEQ responses.
    pub r: Vec<Vec<u8>>,

    /// Lagrange coefficients.
    pub coefficients: Vec<Vec<u8>>,
}

impl TOPRFProofPublicInputs {
    /// Create from TOPRFPublicInputs.
    pub fn from_inputs(inputs: &TOPRFPublicInputs) -> Self {
        Self {
            domain_separator: inputs.domain_separator.to_bytes_be().to_vec(),
            output: inputs.output.to_bytes_be().to_vec(),
            responses: inputs.responses.iter().map(|p| {
                (p.x.to_bytes_be().to_vec(), p.y.to_bytes_be().to_vec())
            }).collect(),
            share_public_keys: inputs.share_public_keys.iter().map(|p| {
                (p.x.to_bytes_be().to_vec(), p.y.to_bytes_be().to_vec())
            }).collect(),
            c: inputs.c.iter().map(|v| v.to_bytes_be().to_vec()).collect(),
            r: inputs.r.iter().map(|v| v.to_bytes_be().to_vec()).collect(),
            coefficients: inputs.coefficients.iter().map(|v| v.to_bytes_be().to_vec()).collect(),
        }
    }

    /// Verify that inputs match this public input commitment.
    pub fn verify(&self, inputs: &TOPRFPublicInputs) -> bool {
        let other = Self::from_inputs(inputs);
        self.domain_separator == other.domain_separator
            && self.output == other.output
            && self.responses == other.responses
            && self.share_public_keys == other.share_public_keys
            && self.c == other.c
            && self.r == other.r
            && self.coefficients == other.coefficients
    }

    /// Mix into Fiat-Shamir channel.
    fn mix_into(&self, channel: &mut impl Channel) {
        // Mix all public inputs as bytes
        for byte in &self.domain_separator {
            channel.mix_u64(*byte as u64);
        }
        for byte in &self.output {
            channel.mix_u64(*byte as u64);
        }
        for (x, y) in &self.responses {
            for byte in x {
                channel.mix_u64(*byte as u64);
            }
            for byte in y {
                channel.mix_u64(*byte as u64);
            }
        }
        for (x, y) in &self.share_public_keys {
            for byte in x {
                channel.mix_u64(*byte as u64);
            }
            for byte in y {
                channel.mix_u64(*byte as u64);
            }
        }
        for c_val in &self.c {
            for byte in c_val {
                channel.mix_u64(*byte as u64);
            }
        }
        for r_val in &self.r {
            for byte in r_val {
                channel.mix_u64(*byte as u64);
            }
        }
        for coeff in &self.coefficients {
            for byte in coeff {
                channel.mix_u64(*byte as u64);
            }
        }
    }
}

/// Statement for TOPRF verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOPRFStatement {
    pub log_size: u32,
    pub public_inputs: TOPRFProofPublicInputs,
}

impl TOPRFStatement {
    fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        let info = toprf_info();
        let n_trace_cols = info.mask_offsets[1].len();
        TreeVec::new(vec![
            vec![],                            // Preprocessed (empty)
            vec![self.log_size; n_trace_cols], // Main trace
        ])
    }

    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
        self.public_inputs.mix_into(channel);
    }
}

/// TOPRF proof structure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TOPRFProof<H: MerkleHasherLifted> {
    pub stmt: TOPRFStatement,
    pub stark_proof: StarkProof<H>,
}

/// Generate trace columns from TOPRF inputs.
fn generate_toprf_trace(
    log_size: u32,
    inputs: &TOPRFInputs,
) -> (Vec<BaseColumn>, BigInt256) {
    let mut gen = TOPRFTraceGen::new();
    let output = gen.gen_toprf(inputs);

    // The trace is stored as Vec<Vec<u32>> where each inner Vec is a column
    let trace_columns = &gen.field_gen.trace;
    let n_rows = 1 << log_size;

    // Get expected number of columns from component info
    let info = toprf_info();
    let n_cols = info.mask_offsets[1].len();

    // Create columns from trace data
    // Each column in trace_columns contains the values for that column
    // IMPORTANT: We replicate the single row of trace data across all rows
    // because stwo evaluates constraints on all rows, and the constraints
    // must hold for each row.
    let columns: Vec<BaseColumn> = (0..n_cols)
        .map(|col_idx| {
            let mut values = vec![M31::from_u32_unchecked(0); n_rows];

            if col_idx < trace_columns.len() {
                let col_data = &trace_columns[col_idx];
                if !col_data.is_empty() {
                    // Replicate the first (and only) trace value across all rows
                    let val = M31::from_u32_unchecked(col_data[0]);
                    for row in 0..n_rows {
                        values[row] = val;
                    }
                }
            }

            BaseColumn::from_cpu(&values)
        })
        .collect();

    (columns, output)
}

/// Prove TOPRF verification with provided inputs.
///
/// # Arguments
/// * `config` - PCS configuration
/// * `inputs` - Full TOPRF inputs (public and private)
///
/// # Returns
/// * TOPRF proof that can be verified without the private inputs
pub fn prove_toprf<MC: MerkleChannel>(
    config: PcsConfig,
    inputs: &TOPRFInputs,
) -> Result<TOPRFProof<MC::H>, String>
where
    SimdBackend: BackendForChannel<MC>,
{
    // Determine log_size based on trace requirements
    // We need enough rows for the SIMD backend
    let log_size = LOG_N_LANES.max(10); // At least 2^10 = 1024 rows

    if log_size > 24 {
        return Err("Trace too large".to_string());
    }

    // Precompute twiddles
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // Setup protocol
    let channel = &mut MC::C::default();
    let mut commitment_scheme = CommitmentSchemeProver::new(config, &twiddles);

    // No preprocessed trace
    let tree_builder = commitment_scheme.tree_builder();
    tree_builder.commit(channel);

    // Generate trace
    let (trace, computed_output) = generate_toprf_trace(log_size, inputs);

    // Verify output matches
    if computed_output != inputs.public.output {
        return Err("Computed output does not match expected output".to_string());
    }

    // Create public inputs
    let public_inputs = TOPRFProofPublicInputs::from_inputs(&inputs.public);
    let stmt = TOPRFStatement { log_size, public_inputs };
    stmt.mix_into(channel);

    // Convert trace columns to CircleEvaluations
    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace_evals: Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> = trace
        .into_iter()
        .map(|col| {
            CircleEvaluation::new(domain, col)
        })
        .collect();

    // Commit trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace_evals);
    tree_builder.commit(channel);

    // Create component
    let tree_span_provider = &mut TraceLocationAllocator::default();
    let component = TOPRFComponent::new(
        tree_span_provider,
        TOPRFEval {
            log_size,
            claimed_sum: SecureField::zero(),
        },
        SecureField::zero(),
    );

    // Prove
    let stark_proof = prove(
        &[&component as &dyn ComponentProver<SimdBackend>],
        channel,
        commitment_scheme,
    )
    .map_err(|e| format!("Proof generation failed: {:?}", e))?;

    Ok(TOPRFProof { stmt, stark_proof })
}

/// Verify TOPRF proof with public inputs validation.
///
/// # Arguments
/// * `proof` - The TOPRF proof
/// * `min_config` - Minimum acceptable PCS config
/// * `expected_output` - The expected TOPRF output hash
///
/// # Returns
/// * Ok(()) if verification succeeds
/// * Err if verification fails
pub fn verify_toprf_with_output<MC: MerkleChannel>(
    proof: TOPRFProof<MC::H>,
    min_config: &PcsConfig,
    expected_output: &[u8],
) -> Result<(), VerificationError> {
    // Validate config
    validate_pcs_config(&proof.stark_proof.config, min_config)?;

    // Verify output matches
    if proof.stmt.public_inputs.output != expected_output {
        return Err(VerificationError::OodsNotMatching);
    }

    verify_toprf_internal::<MC>(proof)
}

/// Verify TOPRF proof without external public input validation.
///
/// WARNING: This function trusts the public inputs embedded in the proof.
pub fn verify_toprf<MC: MerkleChannel>(
    proof: TOPRFProof<MC::H>,
    min_config: &PcsConfig,
) -> Result<(), VerificationError> {
    validate_pcs_config(&proof.stark_proof.config, min_config)?;
    verify_toprf_internal::<MC>(proof)
}

/// Internal verification function.
fn verify_toprf_internal<MC: MerkleChannel>(
    TOPRFProof { stmt, stark_proof }: TOPRFProof<MC::H>,
) -> Result<(), VerificationError> {
    if stark_proof.commitments.len() < 2 {
        return Err(VerificationError::OodsNotMatching);
    }

    let channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(stark_proof.config);

    let log_sizes = stmt.log_sizes();

    // Preprocessed (empty)
    commitment_scheme.commit(stark_proof.commitments[0], &log_sizes[0], channel);

    // Trace
    stmt.mix_into(channel);
    commitment_scheme.commit(stark_proof.commitments[1], &log_sizes[1], channel);

    // Create component
    let tree_span_provider = &mut TraceLocationAllocator::default();
    let component = TOPRFComponent::new(
        tree_span_provider,
        TOPRFEval {
            log_size: stmt.log_size,
            claimed_sum: SecureField::zero(),
        },
        SecureField::zero(),
    );

    verify(
        &[&component as &dyn Component],
        channel,
        commitment_scheme,
        stark_proof,
    )
}

/// Validate PCS config meets minimum security requirements.
fn validate_pcs_config(
    proof_config: &PcsConfig,
    min_config: &PcsConfig,
) -> Result<(), VerificationError> {
    if proof_config.pow_bits < min_config.pow_bits {
        return Err(VerificationError::InvalidStructure(format!(
            "Proof pow_bits ({}) below minimum ({})",
            proof_config.pow_bits, min_config.pow_bits
        )));
    }
    if proof_config.fri_config.log_blowup_factor < min_config.fri_config.log_blowup_factor {
        return Err(VerificationError::InvalidStructure(format!(
            "Proof log_blowup_factor ({}) below minimum ({})",
            proof_config.fri_config.log_blowup_factor,
            min_config.fri_config.log_blowup_factor
        )));
    }
    if proof_config.fri_config.n_queries < min_config.fri_config.n_queries {
        return Err(VerificationError::InvalidStructure(format!(
            "Proof n_queries ({}) below minimum ({})",
            proof_config.fri_config.n_queries,
            min_config.fri_config.n_queries
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;

    use crate::babyjub::toprf::gen::verify_toprf_native;
    use crate::toprf_server::dkg::{generate_shared_key, random_scalar};
    use crate::toprf_server::eval::{evaluate_oprf_mimc, hash_to_point_mimc, mask_point};
    use crate::babyjub::field256::gen::{modulus, scalar_order};
    use crate::babyjub::mimc_compat::mimc_hash;
    use crate::babyjub::point::gen::native;
    use crate::babyjub::point::AffinePointBigInt;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Create valid TOPRF inputs for testing.
    fn create_valid_inputs() -> TOPRFInputs {
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let p = modulus();
        let order = scalar_order();

        let secret_data = [
            BigInt256::from_u64(0x00DE_006F),
            BigInt256::from_u64(0x01BC_014D),
        ];
        let domain_separator = BigInt256::from_u32(1);

        let shared_key = generate_shared_key(&mut rng, 1, 1);
        let share = &shared_key.shares[0];

        let data_point = hash_to_point_mimc(&secret_data, &domain_separator);
        let mask = random_scalar(&mut rng);
        let masked_request = mask_point(&data_point, &mask);

        let response = evaluate_oprf_mimc(&mut rng, share, &masked_request)
            .expect("OPRF evaluation should succeed");

        let mask_inv = mask.inv_mod(&order).expect("mask should have inverse");
        let unmasked = native::scalar_mul(&response.evaluated_point, &mask_inv);

        let (unmasked_x, unmasked_y) = unmasked.to_affine(&p);
        let output_hash = mimc_hash(&[
            unmasked_x,
            unmasked_y,
            secret_data[0],
            secret_data[1],
        ]);

        let (resp_x, resp_y) = response.evaluated_point.to_affine(&p);
        let (pub_x, pub_y) = share.public_key.to_affine(&p);

        TOPRFInputs {
            private: super::super::TOPRFPrivateInputs {
                mask,
                secret_data,
            },
            public: super::super::TOPRFPublicInputs {
                domain_separator,
                responses: [AffinePointBigInt { x: resp_x, y: resp_y }],
                coefficients: [BigInt256::one()],
                share_public_keys: [AffinePointBigInt { x: pub_x, y: pub_y }],
                c: [response.c],
                r: [response.r],
                output: output_hash,
            },
        }
    }

    #[test]
    fn test_toprf_info() {
        let info = toprf_info();
        let n_cols = info.mask_offsets[1].len();
        println!("TOPRF trace columns: {}", n_cols);
        println!("TOPRF constraints: {}", info.n_constraints);

        // Verify trace generator produces matching column count
        let inputs = create_valid_inputs();
        let mut gen = TOPRFTraceGen::new();
        let _ = gen.gen_toprf(&inputs);
        assert_eq!(n_cols, gen.field_gen.trace.len(),
            "Column count mismatch: expected {}, got {}", n_cols, gen.field_gen.trace.len());
    }

    #[test]
    fn test_native_verification_works() {
        let inputs = create_valid_inputs();
        let result = verify_toprf_native(&inputs);
        assert!(result.is_ok(), "Native verification should pass: {:?}", result);
    }

    #[test]
    #[ignore] // Expensive test - run with --ignored
    fn test_toprf_prove_verify() {
        let inputs = create_valid_inputs();
        let config = PcsConfig::default();

        println!("Generating TOPRF proof...");
        let start = std::time::Instant::now();
        let proof = prove_toprf::<Blake2sMerkleChannel>(config, &inputs)
            .expect("Proof generation should succeed");
        println!("Prove time: {:?}", start.elapsed());

        println!("Verifying TOPRF proof...");
        let start = std::time::Instant::now();
        verify_toprf::<Blake2sMerkleChannel>(proof, &PcsConfig::default())
            .expect("Verification should succeed");
        println!("Verify time: {:?}", start.elapsed());
    }
}
