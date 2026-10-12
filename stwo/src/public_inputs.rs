//! Public encryption columns, reconstructed by the verifier and checked by the AIR.

use stwo::core::channel::MerkleChannel;
use stwo::core::fields::m31::BaseField;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::CommitmentSchemeProver;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::EvalAtRow;

pub(crate) type PublicTrace = Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>;

pub(crate) const HEADER_BYTES: usize = 16;

pub(crate) fn public_column_ids(block_size: usize) -> Vec<PreProcessedColumnId> {
    (0..1 + HEADER_BYTES + 2 * block_size)
        .map(|index| PreProcessedColumnId {
            id: format!("encryption_public_{index}"),
        })
        .collect()
}

/// Row order matches the SIMD witness: batch, then lane, in evaluation storage order.
/// Only padding rows have an inactive selector. Every supplied block is constrained.
pub(crate) fn public_trace(
    log_size: u32,
    block_size: usize,
    nonce: &[u8; 12],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> Result<PublicTrace, String> {
    if !(4..=24).contains(&log_size) {
        return Err("Public input log_size must be between 4 and 24".into());
    }
    if plaintext.is_empty()
        || plaintext.len() != ciphertext.len()
        || plaintext.len() % block_size != 0
    {
        return Err("Public inputs must contain equal, nonempty whole blocks".into());
    }
    let n_blocks = plaintext.len() / block_size;
    let n_rows = 1usize << log_size;
    if n_blocks > n_rows {
        return Err("Public inputs exceed the trace capacity".into());
    }
    if counter.checked_add(n_blocks as u32 - 1).is_none() {
        return Err("Public input counter overflows".into());
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    Ok((0..1 + HEADER_BYTES + 2 * block_size)
        .map(|column| {
            let values: BaseColumn = (0..n_rows)
                .map(|row| {
                    let value = if row >= n_blocks {
                        0
                    } else if column == 0 {
                        1
                    } else {
                        let byte = column - 1;
                        if byte < 12 {
                            nonce[byte]
                        } else if byte < HEADER_BYTES {
                            let value = counter + row as u32;
                            let bytes = if block_size == 16 {
                                value.to_be_bytes()
                            } else {
                                value.to_le_bytes()
                            };
                            bytes[byte - 12]
                        } else if byte < HEADER_BYTES + block_size {
                            plaintext[row * block_size + byte - HEADER_BYTES]
                        } else {
                            ciphertext[row * block_size + byte - HEADER_BYTES - block_size]
                        }
                    };
                    BaseField::from_u32_unchecked(value as u32)
                })
                .collect();
            CircleEvaluation::new(domain, values)
        })
        .collect())
}

/// Recompute the entire preprocessed commitment, including any fixed lookup tables.
/// Accepting the prover's root without this comparison leaves public columns unbound.
pub(crate) fn preprocessed_root<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
    trace: PublicTrace,
) -> <MC::H as MerkleHasherLifted>::Hash
where
    SimdBackend: BackendForChannel<MC>,
{
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(log_size + 1 + config.fri_config.log_blowup_factor)
            .circle_domain()
            .half_coset,
    );
    let mut scheme = CommitmentSchemeProver::<SimdBackend, MC>::new(config, &twiddles);
    let mut builder = scheme.tree_builder();
    builder.extend_evals(trace);
    builder.commit(&mut MC::C::default());
    scheme.roots()[0]
}

pub(crate) struct PublicRow<F> {
    active: F,
    bytes: Vec<F>,
}

impl<F: Clone + std::ops::Sub<Output = F> + std::ops::Mul<Output = F>> PublicRow<F> {
    pub(crate) fn read<E: EvalAtRow<F = F>>(eval: &mut E, block_size: usize) -> Self {
        let mut ids = public_column_ids(block_size).into_iter();
        let active = eval.get_preprocessed_column(ids.next().unwrap());
        let bytes = ids.map(|id| eval.get_preprocessed_column(id)).collect();
        Self { active, bytes }
    }

    pub(crate) fn bind<E: EvalAtRow<F = F>>(&self, eval: &mut E, value: F, byte: usize) {
        eval.add_constraint(self.active.clone() * (value - self.bytes[byte].clone()));
    }
}
