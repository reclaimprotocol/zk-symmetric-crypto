//! AIR for ChaCha20 stream encryption (bitwise with plaintext XOR).

use std::simd::u32x16;

use itertools::Itertools;
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
use stwo_constraint_framework::TraceLocationAllocator;

use super::{
    chacha_stream_info, generate_stream_trace, ChaChaStreamComponent, ChaChaStreamEval,
    ChaChaStreamInput,
};

/// Statement for ChaCha20 stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamStatement {
    pub log_size: u32,
}

impl StreamStatement {
    fn log_sizes(&self) -> TreeVec<Vec<u32>> {
        let info = chacha_stream_info();
        let n_trace_cols = info.mask_offsets[1].len();
        TreeVec::new(vec![
            vec![],                            // Preprocessed (empty)
            vec![self.log_size; n_trace_cols], // Main trace
        ])
    }

    fn mix_into(&self, channel: &mut impl Channel) {
        channel.mix_u64(self.log_size as u64);
    }
}

/// ChaCha20 stream proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamProof<H: MerkleHasherLifted> {
    pub stmt: StreamStatement,
    pub stark_proof: StarkProof<H>,
}

/// Prove ChaCha20 stream encryption with provided inputs.
pub fn prove_stream_with_inputs<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
    inputs: &[ChaChaStreamInput],
) -> Result<StreamProof<MC::H>, String>
where
    SimdBackend: BackendForChannel<MC>,
{
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

    // Setup protocol
    let channel = &mut MC::C::default();
    let mut commitment_scheme = CommitmentSchemeProver::new(config, &twiddles);

    // No preprocessed trace
    let tree_builder = commitment_scheme.tree_builder();
    tree_builder.commit(channel);

    // Generate trace
    let (trace, valid) = generate_stream_trace(log_size, inputs);
    if !valid {
        return Err("Ciphertext does not match encryption - invalid witness".to_string());
    }

    // Statement
    let stmt = StreamStatement { log_size };
    stmt.mix_into(channel);

    // Commit trace
    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace.into_iter().collect_vec());
    tree_builder.commit(channel);

    // Create component
    let tree_span_provider = &mut TraceLocationAllocator::default();
    let component = ChaChaStreamComponent::new(
        tree_span_provider,
        ChaChaStreamEval {
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

    Ok(StreamProof { stmt, stark_proof })
}

/// Prove ChaCha20 stream encryption with test data (for benchmarks/tests).
pub fn prove_stream<MC: MerkleChannel>(log_size: u32, config: PcsConfig) -> StreamProof<MC::H>
where
    SimdBackend: BackendForChannel<MC>,
{
    use super::gen_stream::chacha20_encrypt;

    // Test key and nonce
    let key: [u32; 8] = [
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    ];
    let nonce: [u32; 3] = [0x00000000, 0x0000004a, 0x00000000];

    // Generate inputs with incrementing counters, plaintext, and correct ciphertext
    let inputs: Vec<ChaChaStreamInput> = (0..(1 << (log_size - LOG_N_LANES)))
        .map(|i| {
            let counters = u32x16::from_array(std::array::from_fn(|lane| (i * 16 + lane + 1) as u32));

            // Test plaintext pattern
            let plaintext: [u32x16; 16] = std::array::from_fn(|word| {
                u32x16::from_array(std::array::from_fn(|lane| {
                    ((i * 16 + lane) * 16 + word) as u32
                }))
            });

            // Compute correct ciphertext for each lane
            let mut ciphertext: [u32x16; 16] = [u32x16::splat(0); 16];
            for lane in 0..16 {
                let counter = (i * 16 + lane + 1) as u32;
                let pt: [u32; 16] = std::array::from_fn(|w| plaintext[w][lane]);
                let ct = chacha20_encrypt(&key, &nonce, counter, &pt);
                for w in 0..16 {
                    ciphertext[w][lane] = ct[w];
                }
            }

            ChaChaStreamInput {
                key,
                nonce,
                counters,
                plaintext,
                ciphertext,
            }
        })
        .collect();

    prove_stream_with_inputs::<MC>(log_size, config, &inputs)
        .expect("Test data should produce valid proof")
}

/// Verify ChaCha20 stream proof.
pub fn verify_stream<MC: MerkleChannel>(
    StreamProof { stmt, stark_proof }: StreamProof<MC::H>,
) -> Result<(), VerificationError> {
    // Validate commitment count before indexing
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
    let component = ChaChaStreamComponent::new(
        tree_span_provider,
        ChaChaStreamEval {
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
    fn test_stream_prove_verify() {
        let log_size = 6; // 64 blocks
        let config = PcsConfig::default();

        let n_blocks = 1 << log_size;
        let bytes = n_blocks * 64; // ChaCha block = 64 bytes
        println!(
            "Proving {} ChaCha20 stream blocks ({} bytes)...",
            n_blocks, bytes
        );

        let start = Instant::now();
        let proof = prove_stream::<Blake2sMerkleChannel>(log_size, config);
        let prove_time = start.elapsed();
        println!("Prove time: {:?}", prove_time);

        let start = Instant::now();
        verify_stream::<Blake2sMerkleChannel>(proof).unwrap();
        let verify_time = start.elapsed();
        println!("Verify time: {:?}", verify_time);
    }

    #[test]
    #[ignore]
    fn bench_stream() {
        for log_size in [4, 5, 6, 7, 8] {
            let config = PcsConfig::default();
            let n_blocks = 1 << log_size;
            let bytes = n_blocks * 64;

            println!(
                "\n=== ChaCha20 Stream log_size={} ({} blocks, {} bytes) ===",
                log_size, n_blocks, bytes
            );

            let start = Instant::now();
            let proof = prove_stream::<Blake2sMerkleChannel>(log_size, config);
            let prove_time = start.elapsed();

            let start = Instant::now();
            verify_stream::<Blake2sMerkleChannel>(proof).unwrap();
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
