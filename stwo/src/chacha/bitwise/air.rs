//! Simple AIR for bitwise ChaCha20 (no lookup tables).

use std::simd::u32x16;

use itertools::Itertools;
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
use stwo_constraint_framework::TraceLocationAllocator;

use super::{
    chacha_bitwise_info, generate_trace, ChaChabitwiseComponent, ChaChabitwiseEval,
    ChaChabitwiseInput,
};
use crate::chacha::block::build_state;

/// Statement for bitwise ChaCha.
pub struct BitwiseStatement {
    pub log_size: u32,
}

impl BitwiseStatement {
    fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        let info = chacha_bitwise_info();
        let n_trace_cols = info.mask_offsets[1].len(); // Original trace columns
        // Only 2 trees for bitwise (no interaction trace needed)
        TreeVec::new(vec![
            vec![],                                    // Preprocessed (empty)
            vec![self.log_size; n_trace_cols],         // Main trace
        ])
    }

    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
    }
}

/// Bitwise ChaCha proof.
pub struct BitwiseProof<H: MerkleHasherLifted> {
    pub stmt: BitwiseStatement,
    pub stark_proof: StarkProof<H>,
}

/// Prove bitwise ChaCha20.
pub fn prove_bitwise<MC: MerkleChannel>(log_size: u32, config: PcsConfig) -> BitwiseProof<MC::H>
where
    SimdBackend: BackendForChannel<MC>,
{
    assert!(log_size >= LOG_N_LANES);

    // Precompute twiddles
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );

    // Prepare inputs
    let key: [u32; 8] = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    ];
    let nonce: [u32; 3] = [0x09000000, 0x4a000000, 0x00000000];

    let inputs: Vec<ChaChabitwiseInput> = (0..(1 << (log_size - LOG_N_LANES)))
        .map(|i| {
            let counters = u32x16::from_array(std::array::from_fn(|lane| (i * 16 + lane) as u32));
            let base_state = build_state(&key, 0, &nonce);
            ChaChabitwiseInput {
                initial_state: std::array::from_fn(|j| {
                    if j == 12 {
                        counters
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

    // No preprocessed trace for bitwise version
    let tree_builder = commitment_scheme.tree_builder();
    tree_builder.commit(channel);

    // Generate trace
    let trace = generate_trace(log_size, &inputs);

    // Statement
    let stmt = BitwiseStatement { log_size };
    stmt.mix_into(channel);

    // Commit trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace.into_iter().collect_vec());
    tree_builder.commit(channel);

    // Create component (no interaction trace needed for bitwise)
    let tree_span_provider = &mut TraceLocationAllocator::default();
    let component = ChaChabitwiseComponent::new(
        tree_span_provider,
        ChaChabitwiseEval {
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
    .unwrap();

    BitwiseProof { stmt, stark_proof }
}

/// Verify bitwise ChaCha20 proof.
pub fn verify_bitwise<MC: MerkleChannel>(
    BitwiseProof { stmt, stark_proof }: BitwiseProof<MC::H>,
) -> Result<(), VerificationError> {
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
    let component = ChaChabitwiseComponent::new(
        tree_span_provider,
        ChaChabitwiseEval {
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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use stwo::core::pcs::PcsConfig;
    use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;

    use super::*;

    #[test]
    #[ignore]
    fn test_bitwise_prove_verify() {
        let log_size = 6; // 64 blocks
        let config = PcsConfig::default();

        let n_blocks = 1 << log_size;
        println!("Proving {} blocks (bitwise)...", n_blocks);

        let start = Instant::now();
        let proof = prove_bitwise::<Blake2sMerkleChannel>(log_size, config);
        let prove_time = start.elapsed();
        println!("Prove time: {:?}", prove_time);

        let start = Instant::now();
        verify_bitwise::<Blake2sMerkleChannel>(proof).unwrap();
        let verify_time = start.elapsed();
        println!("Verify time: {:?}", verify_time);
    }

    #[test]
    #[ignore]
    fn bench_bitwise() {
        for log_size in [4, 5, 6, 7, 8, 10, 12] {
            let config = PcsConfig::default();
            let n_blocks = 1 << log_size;
            let keystream_bytes = n_blocks * 64;

            println!(
                "\n=== Bitwise log_size={} ({} blocks, {} bytes) ===",
                log_size, n_blocks, keystream_bytes
            );

            let start = Instant::now();
            let proof = prove_bitwise::<Blake2sMerkleChannel>(log_size, config);
            let prove_time = start.elapsed();

            let start = Instant::now();
            verify_bitwise::<Blake2sMerkleChannel>(proof).unwrap();
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
