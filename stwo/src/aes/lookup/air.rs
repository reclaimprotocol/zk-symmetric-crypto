//! AIR for lookup-based AES-128 with full S-box proof.

use std::simd::Simd;

use itertools::{chain, Itertools};
use num_traits::Zero;
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

use super::gen::{
    generate_sbox_interaction_trace, generate_sbox_table_interaction_trace, generate_trace,
    AESLookupInput,
};
use super::{aes_lookup_info, AESLookupComponent, AESLookupEval};
use crate::aes::sbox_table::{
    generate_sbox_trace, sbox_column_id, SboxElements, SboxTableComponent, SboxTableEval,
    SBOX_BITS,
};

/// IDs for preprocessed S-box columns.
fn preprocessed_sbox_columns() -> [PreProcessedColumnId; 2] {
    [sbox_column_id(0), sbox_column_id(1)]
}

/// Statement for lookup-based AES (before interaction).
pub struct AESLookupStatement0 {
    pub log_size: u32,
}

impl AESLookupStatement0 {
    fn log_sizes(&self, n_aes_interaction_cols: usize, n_sbox_interaction_cols: usize) -> TreeVec<Vec<u32>> {
        let info = aes_lookup_info();
        let n_aes_trace_cols = info.mask_offsets[1].len();

        // Trees: preprocessed, main trace, interaction trace
        TreeVec::new(vec![
            // Tree 0: Preprocessed S-box table (input, output columns)
            vec![SBOX_BITS; 2],
            // Tree 1: Main trace (AES columns at log_size, S-box multiplicity at SBOX_BITS)
            chain![
                vec![self.log_size; n_aes_trace_cols],
                vec![SBOX_BITS; 1],  // S-box multiplicity
            ].collect(),
            // Tree 2: Interaction trace
            chain![
                vec![self.log_size; n_aes_interaction_cols],
                vec![SBOX_BITS; n_sbox_interaction_cols],
            ].collect(),
        ])
    }

    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
    }
}

/// Statement for lookup-based AES (after interaction).
pub struct AESLookupStatement1 {
    pub aes_claimed_sum: SecureField,
    pub sbox_table_claimed_sum: SecureField,
    pub n_aes_interaction_cols: usize,
    pub n_sbox_interaction_cols: usize,
}

impl AESLookupStatement1 {
    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_felts(&[self.aes_claimed_sum, self.sbox_table_claimed_sum]);
    }
}

/// AES lookup proof.
pub struct AESLookupProof<H: MerkleHasherLifted> {
    pub stmt0: AESLookupStatement0,
    pub stmt1: AESLookupStatement1,
    pub stark_proof: StarkProof<H>,
}

/// All components for AES lookup proof.
pub struct AESComponents {
    aes_component: AESLookupComponent,
    sbox_table_component: SboxTableComponent,
}

impl AESComponents {
    fn new(
        stmt0: &AESLookupStatement0,
        sbox_elements: &SboxElements,
        stmt1: &AESLookupStatement1,
    ) -> Self {
        let tree_span_provider =
            &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_sbox_columns());

        Self {
            aes_component: AESLookupComponent::new(
                tree_span_provider,
                AESLookupEval {
                    log_size: stmt0.log_size,
                    sbox_lookup_elements: sbox_elements.clone(),
                    claimed_sum: stmt1.aes_claimed_sum,
                },
                stmt1.aes_claimed_sum,
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
            &self.aes_component as &dyn Component,
            &self.sbox_table_component as &dyn Component,
        ]
    }

    fn component_provers(&self) -> Vec<&dyn ComponentProver<SimdBackend>> {
        vec![
            &self.aes_component as &dyn ComponentProver<SimdBackend>,
            &self.sbox_table_component as &dyn ComponentProver<SimdBackend>,
        ]
    }
}

/// Prove AES-128 encryption using lookup tables with full S-box verification.
pub fn prove_aes_lookup<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
) -> AESLookupProof<MC::H>
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

    // Prepare test inputs
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    let inputs: Vec<AESLookupInput> = (0..(1 << (log_size - LOG_N_LANES)))
        .map(|i| {
            let plaintext: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
                Simd::from_array(std::array::from_fn(|lane| {
                    ((i * 16 + lane + byte_idx) & 0xFF) as u8
                }))
            });
            let key_simd: [Simd<u8, 16>; 16] =
                std::array::from_fn(|byte_idx| Simd::splat(key[byte_idx]));
            AESLookupInput {
                plaintext,
                key: key_simd,
            }
        })
        .collect();

    // Setup protocol
    let channel = &mut MC::C::default();
    let mut commitment_scheme = CommitmentSchemeProver::new(config, &twiddles);

    // Generate and commit preprocessed S-box table columns
    let sbox_preprocessed_trace = generate_sbox_trace();
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(sbox_preprocessed_trace);
    tree_builder.commit(channel);

    // Generate main trace (AES component)
    let (trace, sbox_accum, lookup_data) = generate_trace(log_size, &inputs);

    // Generate S-box table multiplicity trace
    let sbox_mult_col = sbox_accum.clone().into_base_column();
    let sbox_mult_trace = stwo::prover::poly::circle::CircleEvaluation::new(
        CanonicCoset::new(SBOX_BITS).circle_domain(),
        sbox_mult_col,
    );

    // Statement0
    let stmt0 = AESLookupStatement0 { log_size };
    stmt0.mix_into(channel);

    // Commit main trace (AES component + S-box multiplicities)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(chain![trace, [sbox_mult_trace]].collect_vec());
    tree_builder.commit(channel);

    // Draw lookup elements
    let sbox_elements = SboxElements::draw(channel);

    // Generate interaction traces
    let (aes_interaction_trace, aes_claimed_sum) =
        generate_sbox_interaction_trace(log_size, &sbox_accum, &lookup_data, &sbox_elements);

    let (sbox_table_interaction_trace, sbox_table_claimed_sum) =
        generate_sbox_table_interaction_trace(&sbox_accum, &sbox_elements);

    // Statement1
    let n_aes_interaction_cols = aes_interaction_trace.len();
    let n_sbox_interaction_cols = sbox_table_interaction_trace.len();
    let stmt1 = AESLookupStatement1 {
        aes_claimed_sum,
        sbox_table_claimed_sum,
        n_aes_interaction_cols,
        n_sbox_interaction_cols,
    };
    stmt1.mix_into(channel);

    // Commit interaction trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![aes_interaction_trace, sbox_table_interaction_trace].collect_vec(),
    );
    tree_builder.commit(channel);

    // Verify that sums balance (should sum to zero for valid lookup)
    let total_sum = aes_claimed_sum + sbox_table_claimed_sum;
    assert_eq!(
        total_sum,
        SecureField::zero(),
        "LogUp sums don't balance: {:?}",
        total_sum
    );

    // Create components
    let components = AESComponents::new(&stmt0, &sbox_elements, &stmt1);

    // Prove
    let stark_proof = prove(&components.component_provers(), channel, commitment_scheme).unwrap();

    AESLookupProof {
        stmt0,
        stmt1,
        stark_proof,
    }
}

/// Verify AES-128 lookup proof.
pub fn verify_aes_lookup<MC: MerkleChannel>(
    AESLookupProof {
        stmt0,
        stmt1,
        stark_proof,
    }: AESLookupProof<MC::H>,
) -> Result<(), VerificationError> {
    let channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(stark_proof.config);

    let log_sizes = stmt0.log_sizes(stmt1.n_aes_interaction_cols, stmt1.n_sbox_interaction_cols);

    // Preprocessed (empty)
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
    let total_sum = stmt1.aes_claimed_sum + stmt1.sbox_table_claimed_sum;
    if total_sum != SecureField::zero() {
        return Err(VerificationError::OodsNotMatching);
    }

    // Create components
    let components = AESComponents::new(&stmt0, &sbox_elements, &stmt1);

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
    fn test_aes_lookup_prove_verify() {
        let log_size = 8; // 256 blocks (minimum for S-box table)
        let config = PcsConfig::default();

        let n_blocks = 1 << log_size;
        println!("Proving {} AES blocks (lookup with full S-box proof)...", n_blocks);

        let start = Instant::now();
        let proof = prove_aes_lookup::<Blake2sMerkleChannel>(log_size, config);
        let prove_time = start.elapsed();
        println!("Prove time: {:?}", prove_time);
        println!("AES interaction cols: {}", proof.stmt1.n_aes_interaction_cols);
        println!("S-box table interaction cols: {}", proof.stmt1.n_sbox_interaction_cols);
        println!("AES claimed_sum: {:?}", proof.stmt1.aes_claimed_sum);
        println!("S-box table claimed_sum: {:?}", proof.stmt1.sbox_table_claimed_sum);

        let start = Instant::now();
        verify_aes_lookup::<Blake2sMerkleChannel>(proof).unwrap();
        let verify_time = start.elapsed();
        println!("Verify time: {:?}", verify_time);
    }

    #[test]
    #[ignore]
    fn bench_aes_lookup() {
        // log_size must be >= 8 for S-box table (256 entries)
        for log_size in [8, 9, 10, 12] {
            let config = PcsConfig::default();
            let n_blocks = 1 << log_size;
            let ciphertext_bytes = n_blocks * 16; // AES block = 16 bytes

            println!(
                "\n=== AES Lookup log_size={} ({} blocks, {} bytes) ===",
                log_size, n_blocks, ciphertext_bytes
            );

            let start = Instant::now();
            let proof = prove_aes_lookup::<Blake2sMerkleChannel>(log_size, config);
            let prove_time = start.elapsed();

            let start = Instant::now();
            verify_aes_lookup::<Blake2sMerkleChannel>(proof).unwrap();
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
