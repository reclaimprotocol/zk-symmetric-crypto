//! ChaCha20 AIR (Algebraic Intermediate Representation) for proving and verification.
//!
//! This module implements the full proving and verification system for ChaCha20 full blocks
//! using Stwo's STARK prover.

use std::simd::u32x16;

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
use stwo_constraint_framework::{TraceLocationAllocator, PREPROCESSED_TRACE_IDX};

use super::block::build_state;
use super::block_air::{
    chacha_block_info, generate_interaction_trace, generate_trace, ChaChaBlockComponent,
    ChaChaBlockEval, ChaChaBlockInput,
};
use super::constraints::ChaChaXorElements;
use super::xor_table::{xor12, xor4, xor7, xor8, xor9, XorAccums, XorTable};

/// Preprocessed XOR table column IDs.
fn preprocessed_xor_columns() -> [PreProcessedColumnId; 15] {
    [
        XorTable::new(12, 4, 0).id(),
        XorTable::new(12, 4, 1).id(),
        XorTable::new(12, 4, 2).id(),
        XorTable::new(9, 2, 0).id(),
        XorTable::new(9, 2, 1).id(),
        XorTable::new(9, 2, 2).id(),
        XorTable::new(8, 2, 0).id(),
        XorTable::new(8, 2, 1).id(),
        XorTable::new(8, 2, 2).id(),
        XorTable::new(7, 2, 0).id(),
        XorTable::new(7, 2, 1).id(),
        XorTable::new(7, 2, 2).id(),
        XorTable::new(4, 0, 0).id(),
        XorTable::new(4, 0, 1).id(),
        XorTable::new(4, 0, 2).id(),
    ]
}

/// Log sizes for preprocessed XOR table columns.
const fn preprocessed_xor_columns_log_sizes() -> [u32; 15] {
    [
        XorTable::new(12, 4, 0).column_bits(),
        XorTable::new(12, 4, 1).column_bits(),
        XorTable::new(12, 4, 2).column_bits(),
        XorTable::new(9, 2, 0).column_bits(),
        XorTable::new(9, 2, 1).column_bits(),
        XorTable::new(9, 2, 2).column_bits(),
        XorTable::new(8, 2, 0).column_bits(),
        XorTable::new(8, 2, 1).column_bits(),
        XorTable::new(8, 2, 2).column_bits(),
        XorTable::new(7, 2, 0).column_bits(),
        XorTable::new(7, 2, 1).column_bits(),
        XorTable::new(7, 2, 2).column_bits(),
        XorTable::new(4, 0, 0).column_bits(),
        XorTable::new(4, 0, 1).column_bits(),
        XorTable::new(4, 0, 2).column_bits(),
    ]
}

/// Statement for phase 0 (before interaction elements).
pub struct ChaChaStatement0 {
    pub log_size: u32,
}

impl ChaChaStatement0 {
    fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        let mut sizes = vec![];

        // Block component trace sizes
        sizes.push(
            chacha_block_info()
                .mask_offsets
                .as_cols_ref()
                .map_cols(|_| self.log_size),
        );

        // XOR table trace sizes
        sizes.push(xor12::trace_sizes());
        sizes.push(xor9::trace_sizes());
        sizes.push(xor8::trace_sizes());
        sizes.push(xor7::trace_sizes());
        sizes.push(xor4::trace_sizes());

        let mut log_sizes = TreeVec::concat_cols(sizes.into_iter());

        // Set preprocessed trace log sizes
        log_sizes[PREPROCESSED_TRACE_IDX] = preprocessed_xor_columns_log_sizes().into();

        log_sizes
    }

    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
    }
}

/// All lookup elements for ChaCha.
pub struct AllElements {
    pub xor_elements: ChaChaXorElements,
}

impl AllElements {
    pub fn draw(channel: &mut impl Channel) -> Self {
        Self {
            xor_elements: ChaChaXorElements::draw(channel),
        }
    }
}

/// Statement for phase 1 (after interaction elements).
pub struct ChaChaStatement1 {
    pub block_claimed_sum: SecureField,
    pub xor12_claimed_sum: SecureField,
    pub xor9_claimed_sum: SecureField,
    pub xor8_claimed_sum: SecureField,
    pub xor7_claimed_sum: SecureField,
    pub xor4_claimed_sum: SecureField,
}

impl ChaChaStatement1 {
    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_felts(&[
            self.block_claimed_sum,
            self.xor12_claimed_sum,
            self.xor9_claimed_sum,
            self.xor8_claimed_sum,
            self.xor7_claimed_sum,
            self.xor4_claimed_sum,
        ]);
    }
}

/// ChaCha proof containing statements and STARK proof.
pub struct ChaChaProof<H: MerkleHasherLifted> {
    pub stmt0: ChaChaStatement0,
    pub stmt1: ChaChaStatement1,
    pub stark_proof: StarkProof<H>,
}

/// All ChaCha components.
pub struct ChaChaComponents {
    pub block_component: ChaChaBlockComponent,
    pub xor12: xor12::XorTableComponent,
    pub xor9: xor9::XorTableComponent,
    pub xor8: xor8::XorTableComponent,
    pub xor7: xor7::XorTableComponent,
    pub xor4: xor4::XorTableComponent,
}

impl ChaChaComponents {
    fn new(stmt0: &ChaChaStatement0, all_elements: &AllElements, stmt1: &ChaChaStatement1) -> Self {
        let tree_span_provider =
            &mut TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_xor_columns());

        Self {
            block_component: ChaChaBlockComponent::new(
                tree_span_provider,
                ChaChaBlockEval {
                    log_size: stmt0.log_size,
                    xor_lookup_elements: all_elements.xor_elements.clone(),
                    claimed_sum: stmt1.block_claimed_sum,
                },
                stmt1.block_claimed_sum,
            ),
            xor12: xor12::XorTableComponent::new(
                tree_span_provider,
                xor12::XorTableEval {
                    lookup_elements: all_elements.xor_elements.xor12.clone(),
                    claimed_sum: stmt1.xor12_claimed_sum,
                },
                stmt1.xor12_claimed_sum,
            ),
            xor9: xor9::XorTableComponent::new(
                tree_span_provider,
                xor9::XorTableEval {
                    lookup_elements: all_elements.xor_elements.xor9.clone(),
                    claimed_sum: stmt1.xor9_claimed_sum,
                },
                stmt1.xor9_claimed_sum,
            ),
            xor8: xor8::XorTableComponent::new(
                tree_span_provider,
                xor8::XorTableEval {
                    lookup_elements: all_elements.xor_elements.xor8.clone(),
                    claimed_sum: stmt1.xor8_claimed_sum,
                },
                stmt1.xor8_claimed_sum,
            ),
            xor7: xor7::XorTableComponent::new(
                tree_span_provider,
                xor7::XorTableEval {
                    lookup_elements: all_elements.xor_elements.xor7.clone(),
                    claimed_sum: stmt1.xor7_claimed_sum,
                },
                stmt1.xor7_claimed_sum,
            ),
            xor4: xor4::XorTableComponent::new(
                tree_span_provider,
                xor4::XorTableEval {
                    lookup_elements: all_elements.xor_elements.xor4.clone(),
                    claimed_sum: stmt1.xor4_claimed_sum,
                },
                stmt1.xor4_claimed_sum,
            ),
        }
    }

    fn components(&self) -> Vec<&dyn Component> {
        vec![
            &self.block_component as &dyn Component,
            &self.xor12 as &dyn Component,
            &self.xor9 as &dyn Component,
            &self.xor8 as &dyn Component,
            &self.xor7 as &dyn Component,
            &self.xor4 as &dyn Component,
        ]
    }

    fn component_provers(&self) -> Vec<&dyn ComponentProver<SimdBackend>> {
        vec![
            &self.block_component as &dyn ComponentProver<SimdBackend>,
            &self.xor12 as &dyn ComponentProver<SimdBackend>,
            &self.xor9 as &dyn ComponentProver<SimdBackend>,
            &self.xor8 as &dyn ComponentProver<SimdBackend>,
            &self.xor7 as &dyn ComponentProver<SimdBackend>,
            &self.xor4 as &dyn ComponentProver<SimdBackend>,
        ]
    }
}

/// Prove ChaCha20 full block computation.
///
/// # Arguments
/// * `log_size` - Log2 of the number of blocks to prove (must be >= LOG_N_LANES)
/// * `config` - PCS configuration
///
/// # Returns
/// A ChaCha proof that can be verified.
#[allow(unused)]
pub fn prove_chacha<MC: MerkleChannel>(log_size: u32, config: PcsConfig) -> ChaChaProof<MC::H>
where
    SimdBackend: BackendForChannel<MC>,
{
    assert!(log_size >= LOG_N_LANES);

    // Precompute twiddles
    const XOR_TABLE_MAX_LOG_SIZE: u32 = 16;
    let log_max_rows = log_size.max(XOR_TABLE_MAX_LOG_SIZE);
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_max_rows + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // Prepare inputs using RFC 7539 test vector
    let key: [u32; 8] = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    ];
    let nonce: [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];

    let inputs: Vec<ChaChaBlockInput> = (0..(1 << (log_size - LOG_N_LANES)))
        .map(|i| {
            // Each SIMD row processes 16 blocks with sequential counters
            let counters = u32x16::from_array(std::array::from_fn(|lane| (i * 16 + lane) as u32));
            let base_state = build_state(&key, 0, &nonce);
            ChaChaBlockInput {
                initial_state: std::array::from_fn(|j| {
                    if j == 12 {
                        counters // Counter position
                    } else {
                        u32x16::splat(base_state[j])
                    }
                }),
            }
        })
        .collect();

    // Setup protocol
    let channel = &mut MC::C::default();
    let mut commitment_scheme = CommitmentSchemeProver::new(config, &twiddles);

    // Preprocessed trace (XOR table constants)
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![
            XorTable::new(12, 4, 0).generate_constant_trace(),
            XorTable::new(9, 2, 0).generate_constant_trace(),
            XorTable::new(8, 2, 0).generate_constant_trace(),
            XorTable::new(7, 2, 0).generate_constant_trace(),
            XorTable::new(4, 0, 0).generate_constant_trace(),
        ]
        .collect_vec(),
    );
    tree_builder.commit(channel);

    // Generate block trace
    let mut xor_accums = XorAccums::new();
    let (block_trace, block_lookup_data) = generate_trace(log_size, &inputs, &mut xor_accums);

    // Generate XOR table traces
    let (xor_trace12, xor_lookup_data12) =
        xor12::generate_trace(xor_accums.xor12.take().unwrap());
    let (xor_trace9, xor_lookup_data9) = xor9::generate_trace(xor_accums.xor9.take().unwrap());
    let (xor_trace8, xor_lookup_data8) = xor8::generate_trace(xor_accums.xor8.take().unwrap());
    let (xor_trace7, xor_lookup_data7) = xor7::generate_trace(xor_accums.xor7.take().unwrap());
    let (xor_trace4, xor_lookup_data4) = xor4::generate_trace(xor_accums.xor4.take().unwrap());

    // Statement0
    let stmt0 = ChaChaStatement0 { log_size };
    stmt0.mix_into(channel);

    // Trace commitment
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![
            block_trace,
            xor_trace12,
            xor_trace9,
            xor_trace8,
            xor_trace7,
            xor_trace4,
        ]
        .collect_vec(),
    );
    tree_builder.commit(channel);

    // Draw lookup elements
    let all_elements = AllElements::draw(channel);

    // Interaction trace
    let (block_interaction_trace, block_claimed_sum) = generate_interaction_trace(
        log_size,
        block_lookup_data,
        &all_elements.xor_elements,
    );

    let (xor_trace12, xor12_claimed_sum) =
        xor12::generate_interaction_trace(xor_lookup_data12, &all_elements.xor_elements.xor12);
    let (xor_trace9, xor9_claimed_sum) =
        xor9::generate_interaction_trace(xor_lookup_data9, &all_elements.xor_elements.xor9);
    let (xor_trace8, xor8_claimed_sum) =
        xor8::generate_interaction_trace(xor_lookup_data8, &all_elements.xor_elements.xor8);
    let (xor_trace7, xor7_claimed_sum) =
        xor7::generate_interaction_trace(xor_lookup_data7, &all_elements.xor_elements.xor7);
    let (xor_trace4, xor4_claimed_sum) =
        xor4::generate_interaction_trace(xor_lookup_data4, &all_elements.xor_elements.xor4);

    // Statement1
    let stmt1 = ChaChaStatement1 {
        block_claimed_sum,
        xor12_claimed_sum,
        xor9_claimed_sum,
        xor8_claimed_sum,
        xor7_claimed_sum,
        xor4_claimed_sum,
    };
    stmt1.mix_into(channel);

    // Commit interaction trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(
        chain![
            block_interaction_trace,
            xor_trace12,
            xor_trace9,
            xor_trace8,
            xor_trace7,
            xor_trace4,
        ]
        .collect_vec(),
    );
    tree_builder.commit(channel);

    // Prove constraints
    let components = ChaChaComponents::new(&stmt0, &all_elements, &stmt1);
    let stark_proof = prove(&components.component_provers(), channel, commitment_scheme).unwrap();

    ChaChaProof {
        stmt0,
        stmt1,
        stark_proof,
    }
}

/// Verify a ChaCha20 proof.
#[allow(unused)]
pub fn verify_chacha<MC: MerkleChannel>(
    ChaChaProof {
        stmt0,
        stmt1,
        stark_proof,
    }: ChaChaProof<MC::H>,
) -> Result<(), VerificationError> {
    let channel = &mut MC::C::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<MC>::new(stark_proof.config);

    let log_sizes = stmt0.log_sizes();

    // Preprocessed trace
    commitment_scheme.commit(stark_proof.commitments[0], &log_sizes[0], channel);

    // Trace
    stmt0.mix_into(channel);
    commitment_scheme.commit(stark_proof.commitments[1], &log_sizes[1], channel);

    // Draw interaction elements
    let all_elements = AllElements::draw(channel);

    // Interaction trace
    stmt1.mix_into(channel);
    commitment_scheme.commit(stark_proof.commitments[2], &log_sizes[2], channel);

    let components = ChaChaComponents::new(&stmt0, &all_elements, &stmt1);

    // Check that all sums are correct (should sum to zero for valid LogUp)
    let claimed_sum = stmt1.block_claimed_sum
        + stmt1.xor12_claimed_sum
        + stmt1.xor9_claimed_sum
        + stmt1.xor8_claimed_sum
        + stmt1.xor7_claimed_sum
        + stmt1.xor4_claimed_sum;

    assert_eq!(claimed_sum, SecureField::zero());

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
    #[ignore] // This test is slow, run with --ignored
    fn test_chacha_prove_verify() {
        let log_size = 8; // 256 full blocks = 16 KB keystream
        let config = PcsConfig::default();

        let n_blocks = 1 << log_size;
        let keystream_kb = n_blocks * 64 / 1024;
        println!("Proving {} full blocks ({} KB keystream)...", n_blocks, keystream_kb);

        // Prove
        let start = Instant::now();
        let proof = prove_chacha::<Blake2sMerkleChannel>(log_size, config);
        let prove_time = start.elapsed();
        println!("Prove time: {:?}", prove_time);

        // Verify
        let start = Instant::now();
        verify_chacha::<Blake2sMerkleChannel>(proof).unwrap();
        let verify_time = start.elapsed();
        println!("Verify time: {:?}", verify_time);
    }

    #[test]
    #[ignore]
    fn bench_chacha_prove() {
        // Benchmark at different sizes
        for log_size in [8, 10, 12, 14, 16] {
            let config = PcsConfig::default();
            let n_blocks = 1 << log_size;
            let keystream_kb = n_blocks * 64 / 1024;

            println!(
                "\n=== log_size={} ({} blocks, {} KB keystream) ===",
                log_size, n_blocks, keystream_kb
            );

            let start = Instant::now();
            let proof = prove_chacha::<Blake2sMerkleChannel>(log_size, config);
            let prove_time = start.elapsed();

            let start = Instant::now();
            verify_chacha::<Blake2sMerkleChannel>(proof).unwrap();
            let verify_time = start.elapsed();

            let blocks_per_sec = n_blocks as f64 / prove_time.as_secs_f64();
            let kb_per_sec = keystream_kb as f64 / prove_time.as_secs_f64();
            println!(
                "Prove: {:?} ({:.0} blocks/sec, {:.0} KB/sec)",
                prove_time, blocks_per_sec, kb_per_sec
            );
            println!("Verify: {:?}", verify_time);
        }
    }
}

#[cfg(test)]
mod small_tests {
    use super::*;
    use std::time::Instant;
    use stwo::core::pcs::PcsConfig;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;

    #[test]
    #[ignore]
    fn bench_small_batches() {
        // Test minimum viable sizes
        for log_size in [4, 5, 6, 7, 8] {
            let config = PcsConfig::default();
            let n_blocks = 1 << log_size;
            let keystream_bytes = n_blocks * 64;

            println!(
                "\n=== log_size={} ({} blocks, {} bytes keystream) ===",
                log_size, n_blocks, keystream_bytes
            );

            let start = Instant::now();
            let proof = prove_chacha::<Blake2sMerkleChannel>(log_size, config);
            let prove_time = start.elapsed();

            let start = Instant::now();
            verify_chacha::<Blake2sMerkleChannel>(proof).unwrap();
            let verify_time = start.elapsed();

            println!("Prove: {:?}", prove_time);
            println!("Verify: {:?}", verify_time);
        }
    }
}
