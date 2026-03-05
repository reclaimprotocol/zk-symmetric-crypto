//! AIR for AES-CTR mode with full S-box proof.
//!
//! Supports both AES-128-CTR and AES-256-CTR.

use itertools::{chain, Itertools};
use num_traits::Zero;
use serde::{Serialize, Deserialize};
use stwo::core::air::Component;
use stwo::core::channel::{Channel, MerkleChannel};
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig, TreeVec};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::core::verifier::{verify, VerificationError};
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::{prove, CommitmentSchemeProver, ComponentProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::TraceLocationAllocator;

use super::gen::generate_sbox_table_interaction_trace;
use super::gen_ctr::{
    generate_aes128_ctr_trace, generate_aes256_ctr_trace,
    generate_aes128_ctr_trace_with_inputs, generate_aes256_ctr_trace_with_inputs,
    generate_ctr_sbox_interaction_trace, AESCtrInput,
};
use super::{aes128_ctr_info, aes256_ctr_info, AESCtrComponent, AESCtrEval};
use crate::aes::sbox_table::{
    generate_sbox_trace, sbox_column_id, SboxElements, SboxTableComponent, SboxTableEval,
    SBOX_BITS,
};
use crate::aes::AesKeySize;

/// IDs for preprocessed S-box columns.
fn preprocessed_sbox_columns() -> [PreProcessedColumnId; 2] {
    [sbox_column_id(0), sbox_column_id(1)]
}

/// Statement for AES-CTR (before interaction).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AESCtrStatement0 {
    pub log_size: u32,
    pub key_size: AesKeySize,
}

impl AESCtrStatement0 {
    fn log_sizes(
        &self,
        n_ctr_interaction_cols: usize,
        n_sbox_interaction_cols: usize,
    ) -> TreeVec<Vec<u32>> {
        let info = match self.key_size {
            AesKeySize::Aes128 => aes128_ctr_info(),
            AesKeySize::Aes256 => aes256_ctr_info(),
        };
        let n_ctr_trace_cols = info.mask_offsets[1].len();

        // Trees: preprocessed, main trace, interaction trace
        TreeVec::new(vec![
            // Tree 0: Preprocessed S-box table (input, output columns)
            vec![SBOX_BITS; 2],
            // Tree 1: Main trace (CTR columns at log_size, S-box multiplicity at SBOX_BITS)
            chain![
                vec![self.log_size; n_ctr_trace_cols],
                vec![SBOX_BITS; 1], // S-box multiplicity
            ]
            .collect(),
            // Tree 2: Interaction trace
            chain![
                vec![self.log_size; n_ctr_interaction_cols],
                vec![SBOX_BITS; n_sbox_interaction_cols],
            ]
            .collect(),
        ])
    }

    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
        channel.mix_u64(self.key_size as u64);
    }
}

/// Statement for AES-CTR (after interaction).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AESCtrStatement1 {
    pub ctr_claimed_sum: SecureField,
    pub sbox_table_claimed_sum: SecureField,
    pub n_ctr_interaction_cols: usize,
    pub n_sbox_interaction_cols: usize,
}

impl AESCtrStatement1 {
    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_felts(&[self.ctr_claimed_sum, self.sbox_table_claimed_sum]);
    }
}

/// AES-CTR proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AESCtrProof<H: MerkleHasherLifted> {
    pub stmt0: AESCtrStatement0,
    pub stmt1: AESCtrStatement1,
    pub stark_proof: StarkProof<H>,
}

/// All components for AES-CTR proof.
pub struct AESCtrComponents {
    ctr_component: AESCtrComponent,
    sbox_table_component: SboxTableComponent,
}

impl AESCtrComponents {
    fn new(
        stmt0: &AESCtrStatement0,
        sbox_elements: &SboxElements,
        stmt1: &AESCtrStatement1,
    ) -> Self {
        let tree_span_provider =
            &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_sbox_columns());

        Self {
            ctr_component: AESCtrComponent::new(
                tree_span_provider,
                AESCtrEval {
                    log_size: stmt0.log_size,
                    key_size: stmt0.key_size,
                    sbox_lookup_elements: sbox_elements.clone(),
                    claimed_sum: stmt1.ctr_claimed_sum,
                },
                stmt1.ctr_claimed_sum,
            ),
            sbox_table_component: SboxTableComponent::new(
                tree_span_provider,
                SboxTableEval {
                    lookup_elements: sbox_elements.clone(),
                    claimed_sum: stmt1.sbox_table_claimed_sum,
                },
                stmt1.sbox_table_claimed_sum,
            ),
        }
    }

    fn components(&self) -> Vec<&dyn Component> {
        vec![
            &self.ctr_component as &dyn Component,
            &self.sbox_table_component as &dyn Component,
        ]
    }

    fn component_provers(&self) -> Vec<&dyn ComponentProver<SimdBackend>> {
        vec![
            &self.ctr_component as &dyn ComponentProver<SimdBackend>,
            &self.sbox_table_component as &dyn ComponentProver<SimdBackend>,
        ]
    }
}

/// Prove AES-128-CTR with provided inputs.
pub fn prove_aes128_ctr_with_inputs<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
    key: &[u8; 16],
    inputs: &[AESCtrInput],
) -> Result<AESCtrProof<MC::H>, String>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_aes_ctr_with_inputs_internal::<MC>(log_size, AesKeySize::Aes128, config, key.as_slice(), inputs)
}

/// Prove AES-256-CTR with provided inputs.
pub fn prove_aes256_ctr_with_inputs<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
    key: &[u8; 32],
    inputs: &[AESCtrInput],
) -> Result<AESCtrProof<MC::H>, String>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_aes_ctr_with_inputs_internal::<MC>(log_size, AesKeySize::Aes256, config, key.as_slice(), inputs)
}

/// Prove AES-128-CTR with full S-box verification (test data).
pub fn prove_aes128_ctr<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
) -> AESCtrProof<MC::H>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_aes_ctr_internal::<MC>(log_size, AesKeySize::Aes128, config)
}

/// Prove AES-256-CTR with full S-box verification (test data).
pub fn prove_aes256_ctr<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
) -> AESCtrProof<MC::H>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_aes_ctr_internal::<MC>(log_size, AesKeySize::Aes256, config)
}

/// Internal prove function for AES-CTR with external inputs.
fn prove_aes_ctr_with_inputs_internal<MC: MerkleChannel>(
    log_size: u32,
    key_size: AesKeySize,
    config: PcsConfig,
    key: &[u8],
    inputs: &[AESCtrInput],
) -> Result<AESCtrProof<MC::H>, String>
where
    SimdBackend: BackendForChannel<MC>,
{
    if log_size < SBOX_BITS {
        return Err(format!(
            "log_size ({}) must be >= {} for S-box table",
            log_size, SBOX_BITS
        ));
    }
    if log_size < LOG_N_LANES {
        return Err(format!(
            "log_size ({}) must be >= LOG_N_LANES ({})",
            log_size, LOG_N_LANES
        ));
    }

    // Precompute twiddles
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // Generate trace based on key size
    let (trace, sbox_accum, lookup_data, valid) = match key_size {
        AesKeySize::Aes128 => {
            let key: [u8; 16] = key.try_into().map_err(|_| "Invalid key length for AES-128")?;
            generate_aes128_ctr_trace_with_inputs(log_size, &key, inputs)
        }
        AesKeySize::Aes256 => {
            let key: [u8; 32] = key.try_into().map_err(|_| "Invalid key length for AES-256")?;
            generate_aes256_ctr_trace_with_inputs(log_size, &key, inputs)
        }
    };

    if !valid {
        return Err("Ciphertext does not match encryption - invalid witness".to_string());
    }

    // Setup protocol
    let channel = &mut MC::C::default();
    let mut commitment_scheme = CommitmentSchemeProver::new(config, &twiddles);

    // Generate and commit preprocessed S-box table columns
    let sbox_preprocessed_trace = generate_sbox_trace();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(sbox_preprocessed_trace);
    tree_builder.commit(channel);

    // Generate S-box table multiplicity trace
    let sbox_mult_col = sbox_accum.clone().into_base_column();
    let sbox_mult_trace = stwo::prover::poly::circle::CircleEvaluation::new(
        CanonicCoset::new(SBOX_BITS).circle_domain(),
        sbox_mult_col,
    );

    // Statement0
    let stmt0 = AESCtrStatement0 { log_size, key_size };
    stmt0.mix_into(channel);

    // Commit main trace (CTR component + S-box multiplicities)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(chain![trace, [sbox_mult_trace]].collect_vec());
    tree_builder.commit(channel);

    // Draw lookup elements
    let sbox_elements = SboxElements::draw(channel);

    // Generate interaction traces
    let (ctr_interaction_trace, ctr_claimed_sum) =
        generate_ctr_sbox_interaction_trace(log_size, &lookup_data, &sbox_elements);

    let (sbox_table_interaction_trace, sbox_table_claimed_sum) =
        generate_sbox_table_interaction_trace(&sbox_accum, &sbox_elements);

    // Statement1
    let n_ctr_interaction_cols = ctr_interaction_trace.len();
    let n_sbox_interaction_cols = sbox_table_interaction_trace.len();
    let stmt1 = AESCtrStatement1 {
        ctr_claimed_sum,
        sbox_table_claimed_sum,
        n_ctr_interaction_cols,
        n_sbox_interaction_cols,
    };
    stmt1.mix_into(channel);

    // Commit interaction trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![ctr_interaction_trace, sbox_table_interaction_trace].collect_vec(),
    );
    tree_builder.commit(channel);

    // Verify that sums balance
    let total_sum = ctr_claimed_sum + sbox_table_claimed_sum;
    if total_sum != SecureField::zero() {
        return Err(format!("LogUp sums don't balance: {:?}", total_sum));
    }

    // Create components
    let components = AESCtrComponents::new(&stmt0, &sbox_elements, &stmt1);

    // Prove
    let stark_proof = prove(&components.component_provers(), channel, commitment_scheme)
        .map_err(|e| format!("Proof generation failed: {:?}", e))?;

    Ok(AESCtrProof {
        stmt0,
        stmt1,
        stark_proof,
    })
}

/// Internal prove function for AES-CTR with test data.
fn prove_aes_ctr_internal<MC: MerkleChannel>(
    log_size: u32,
    key_size: AesKeySize,
    config: PcsConfig,
) -> AESCtrProof<MC::H>
where
    SimdBackend: BackendForChannel<MC>,
{
    // Main trace must be at least as large as S-box table (256 entries = log_size 8)
    assert!(
        log_size >= SBOX_BITS,
        "log_size must be >= {} for S-box table",
        SBOX_BITS
    );
    assert!(log_size >= LOG_N_LANES);

    // Precompute twiddles
    let max_log_size = log_size;
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(max_log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // Test key and nonce
    let nonce: [u8; 12] = [0x00; 12];
    let num_blocks = 1 << log_size;

    // Generate trace based on key size
    let (trace, sbox_accum, lookup_data) = match key_size {
        AesKeySize::Aes128 => {
            let key: [u8; 16] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ];
            generate_aes128_ctr_trace(log_size, &key, &nonce, num_blocks)
        }
        AesKeySize::Aes256 => {
            let key: [u8; 32] = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ];
            generate_aes256_ctr_trace(log_size, &key, &nonce, num_blocks)
        }
    };

    // Setup protocol
    let channel = &mut MC::C::default();
    let mut commitment_scheme = CommitmentSchemeProver::new(config, &twiddles);

    // Generate and commit preprocessed S-box table columns
    let sbox_preprocessed_trace = generate_sbox_trace();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(sbox_preprocessed_trace);
    tree_builder.commit(channel);

    // Generate S-box table multiplicity trace
    let sbox_mult_col = sbox_accum.clone().into_base_column();
    let sbox_mult_trace = stwo::prover::poly::circle::CircleEvaluation::new(
        CanonicCoset::new(SBOX_BITS).circle_domain(),
        sbox_mult_col,
    );

    // Statement0
    let stmt0 = AESCtrStatement0 { log_size, key_size };
    stmt0.mix_into(channel);

    // Commit main trace (CTR component + S-box multiplicities)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(chain![trace, [sbox_mult_trace]].collect_vec());
    tree_builder.commit(channel);

    // Draw lookup elements
    let sbox_elements = SboxElements::draw(channel);

    // Generate interaction traces
    let (ctr_interaction_trace, ctr_claimed_sum) =
        generate_ctr_sbox_interaction_trace(log_size, &lookup_data, &sbox_elements);

    let (sbox_table_interaction_trace, sbox_table_claimed_sum) =
        generate_sbox_table_interaction_trace(&sbox_accum, &sbox_elements);

    // Statement1
    let n_ctr_interaction_cols = ctr_interaction_trace.len();
    let n_sbox_interaction_cols = sbox_table_interaction_trace.len();
    let stmt1 = AESCtrStatement1 {
        ctr_claimed_sum,
        sbox_table_claimed_sum,
        n_ctr_interaction_cols,
        n_sbox_interaction_cols,
    };
    stmt1.mix_into(channel);

    // Commit interaction trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![ctr_interaction_trace, sbox_table_interaction_trace].collect_vec(),
    );
    tree_builder.commit(channel);

    // Verify that sums balance (should sum to zero for valid lookup)
    let total_sum = ctr_claimed_sum + sbox_table_claimed_sum;
    assert_eq!(
        total_sum,
        SecureField::zero(),
        "LogUp sums don't balance: {:?}",
        total_sum
    );

    // Create components
    let components = AESCtrComponents::new(&stmt0, &sbox_elements, &stmt1);

    // Prove
    let stark_proof = prove(&components.component_provers(), channel, commitment_scheme).unwrap();

    AESCtrProof {
        stmt0,
        stmt1,
        stark_proof,
    }
}

/// Maximum allowed interaction columns to prevent memory DoS from malformed proofs.
const MAX_INTERACTION_COLS: usize = 1 << 16;

/// Verify AES-CTR proof (works for both AES-128-CTR and AES-256-CTR).
pub fn verify_aes_ctr<MC: MerkleChannel>(
    AESCtrProof {
        stmt0,
        stmt1,
        stark_proof,
    }: AESCtrProof<MC::H>,
) -> Result<(), VerificationError> {
    // Validate interaction column counts to prevent memory DoS
    if stmt1.n_ctr_interaction_cols > MAX_INTERACTION_COLS
        || stmt1.n_sbox_interaction_cols > MAX_INTERACTION_COLS
    {
        return Err(VerificationError::OodsNotMatching);
    }

    // Validate commitment count before indexing
    if stark_proof.commitments.len() < 3 {
        return Err(VerificationError::OodsNotMatching);
    }

    let channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(stark_proof.config);

    let log_sizes = stmt0.log_sizes(stmt1.n_ctr_interaction_cols, stmt1.n_sbox_interaction_cols);

    // Preprocessed
    commitment_scheme.commit(stark_proof.commitments[0], &log_sizes[0], channel);

    // Main trace
    stmt0.mix_into(channel);
    commitment_scheme.commit(stark_proof.commitments[1], &log_sizes[1], channel);

    // Draw lookup elements
    let sbox_elements = SboxElements::draw(channel);

    // Interaction trace
    stmt1.mix_into(channel);
    commitment_scheme.commit(stark_proof.commitments[2], &log_sizes[2], channel);

    // Verify sums balance
    let total_sum = stmt1.ctr_claimed_sum + stmt1.sbox_table_claimed_sum;
    if total_sum != SecureField::zero() {
        return Err(VerificationError::OodsNotMatching);
    }

    // Create components
    let components = AESCtrComponents::new(&stmt0, &sbox_elements, &stmt1);

    verify(
        &components.components(),
        channel,
        commitment_scheme,
        stark_proof,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use stwo::core::pcs::PcsConfig;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;

    use super::*;

    #[test]
    fn test_aes128_ctr_prove_verify() {
        let log_size = 8; // 256 blocks (minimum for S-box table)
        let config = PcsConfig::default();

        let n_blocks = 1 << log_size;
        println!(
            "Proving {} AES-128-CTR blocks (full S-box proof)...",
            n_blocks
        );

        let start = Instant::now();
        let proof = prove_aes128_ctr::<Blake2sMerkleChannel>(log_size, config);
        let prove_time = start.elapsed();
        println!("Prove time: {:?}", prove_time);
        println!("CTR interaction cols: {}", proof.stmt1.n_ctr_interaction_cols);
        println!(
            "S-box table interaction cols: {}",
            proof.stmt1.n_sbox_interaction_cols
        );
        println!("CTR claimed_sum: {:?}", proof.stmt1.ctr_claimed_sum);
        println!(
            "S-box table claimed_sum: {:?}",
            proof.stmt1.sbox_table_claimed_sum
        );

        let start = Instant::now();
        verify_aes_ctr::<Blake2sMerkleChannel>(proof).unwrap();
        let verify_time = start.elapsed();
        println!("Verify time: {:?}", verify_time);
    }

    #[test]
    fn test_aes256_ctr_prove_verify() {
        let log_size = 8; // 256 blocks (minimum for S-box table)
        let config = PcsConfig::default();

        let n_blocks = 1 << log_size;
        println!(
            "Proving {} AES-256-CTR blocks (full S-box proof)...",
            n_blocks
        );

        let start = Instant::now();
        let proof = prove_aes256_ctr::<Blake2sMerkleChannel>(log_size, config);
        let prove_time = start.elapsed();
        println!("Prove time: {:?}", prove_time);
        println!("CTR interaction cols: {}", proof.stmt1.n_ctr_interaction_cols);
        println!(
            "S-box table interaction cols: {}",
            proof.stmt1.n_sbox_interaction_cols
        );

        let start = Instant::now();
        verify_aes_ctr::<Blake2sMerkleChannel>(proof).unwrap();
        let verify_time = start.elapsed();
        println!("Verify time: {:?}", verify_time);
    }

    /// Test proving with a single block (simulating WASM API scenario)
    #[test]
    fn test_aes128_ctr_single_block_prove_verify() {
        use std::simd::Simd;
        use crate::aes::aes128_ctr_block;
        use crate::aes::lookup::gen_ctr::AESCtrInput;

        let key: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let nonce: [u8; 12] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let counter: u32 = 2; // Match AES-CTR startCounter
        let log_size = 8; // Minimum for S-box table
        let config = PcsConfig::default();

        // Create plaintext
        let plaintext: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];

        // Compute expected ciphertext using native function
        let ciphertext = aes128_ctr_block(&key, &nonce, counter, &plaintext);

        // Build counters (16 parallel blocks starting at counter)
        let counters = Simd::from_array(std::array::from_fn(|lane| counter + lane as u32));

        // Build plaintext SIMD - only lane 0 has real data
        let plaintext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                if lane == 0 {
                    plaintext[byte_idx]
                } else {
                    0
                }
            }))
        });

        // Compute padding keystreams using native function
        let padding_keystreams: Vec<[u8; 16]> = (1..16)
            .map(|lane| {
                let padding_counter = counter + lane as u32;
                aes128_ctr_block(&key, &nonce, padding_counter, &[0u8; 16])
            })
            .collect();

        // Build ciphertext SIMD - lane 0 has real ciphertext, others have keystreams
        let ciphertext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                if lane == 0 {
                    ciphertext[byte_idx]
                } else {
                    padding_keystreams[lane - 1][byte_idx]
                }
            }))
        });

        // Create input
        let input = AESCtrInput {
            nonce,
            counters,
            plaintext: plaintext_simd,
            ciphertext: ciphertext_simd,
        };

        println!("Testing single block with padding...");
        let result = prove_aes128_ctr_with_inputs::<Blake2sMerkleChannel>(log_size, config, &key, &[input]);

        match result {
            Ok(proof) => {
                println!("Proof generated successfully");
                verify_aes_ctr::<Blake2sMerkleChannel>(proof).unwrap();
                println!("Verification passed!");
            }
            Err(e) => {
                panic!("Proof generation failed: {}", e);
            }
        }
    }

    #[test]
    #[ignore]
    fn bench_aes_ctr() {
        // log_size must be >= 8 for S-box table (256 entries)
        for log_size in [8, 9, 10, 12] {
            let config = PcsConfig::default();
            let n_blocks = 1 << log_size;
            let ciphertext_bytes = n_blocks * 16; // AES block = 16 bytes

            println!(
                "\n=== AES-128-CTR log_size={} ({} blocks, {} bytes) ===",
                log_size, n_blocks, ciphertext_bytes
            );

            let start = Instant::now();
            let proof = prove_aes128_ctr::<Blake2sMerkleChannel>(log_size, config);
            let prove_time = start.elapsed();

            let start = Instant::now();
            verify_aes_ctr::<Blake2sMerkleChannel>(proof).unwrap();
            let verify_time = start.elapsed();

            let blocks_per_sec = n_blocks as f64 / prove_time.as_secs_f64();
            println!(
                "Prove: {:?} ({:.1} blocks/sec)",
                prove_time, blocks_per_sec
            );
            println!("Verify: {:?}", verify_time);

            println!(
                "\n=== AES-256-CTR log_size={} ({} blocks, {} bytes) ===",
                log_size, n_blocks, ciphertext_bytes
            );

            let start = Instant::now();
            let proof = prove_aes256_ctr::<Blake2sMerkleChannel>(log_size, config);
            let prove_time = start.elapsed();

            let start = Instant::now();
            verify_aes_ctr::<Blake2sMerkleChannel>(proof).unwrap();
            let verify_time = start.elapsed();

            let blocks_per_sec = n_blocks as f64 / prove_time.as_secs_f64();
            println!(
                "Prove: {:?} ({:.1} blocks/sec)",
                prove_time, blocks_per_sec
            );
            println!("Verify: {:?}", verify_time);
        }
    }
}
