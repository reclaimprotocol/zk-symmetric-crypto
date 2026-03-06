//! AIR for AES-CTR mode with full S-box proof.
//!
//! Supports both AES-128-CTR and AES-256-CTR.

use blake2::{Blake2s256, Digest};
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

/// Public inputs for AES-CTR proof - cryptographically bound to the proof via Fiat-Shamir.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AESCtrPublicInputs {
    /// 12-byte nonce
    pub nonce: [u8; 12],
    /// Starting counter value
    pub counter: u32,
    /// Blake2s hash of plaintext (for binding without storing full plaintext)
    pub plaintext_hash: [u8; 32],
    /// Blake2s hash of ciphertext
    pub ciphertext_hash: [u8; 32],
}

impl AESCtrPublicInputs {
    /// Create public inputs from raw data.
    pub fn new(nonce: &[u8; 12], counter: u32, plaintext: &[u8], ciphertext: &[u8]) -> Self {
        let plaintext_hash: [u8; 32] = Blake2s256::digest(plaintext).into();
        let ciphertext_hash: [u8; 32] = Blake2s256::digest(ciphertext).into();
        Self {
            nonce: *nonce,
            counter,
            plaintext_hash,
            ciphertext_hash,
        }
    }

    /// Verify that the provided data matches this public input commitment.
    pub fn verify(&self, nonce: &[u8; 12], counter: u32, plaintext: &[u8], ciphertext: &[u8]) -> bool {
        if self.nonce != *nonce || self.counter != counter {
            return false;
        }
        let plaintext_hash: [u8; 32] = Blake2s256::digest(plaintext).into();
        let ciphertext_hash: [u8; 32] = Blake2s256::digest(ciphertext).into();
        self.plaintext_hash == plaintext_hash && self.ciphertext_hash == ciphertext_hash
    }

    /// Mix into Fiat-Shamir channel.
    fn mix_into(&self, channel: &mut impl Channel) {
        // Mix nonce (as 3 u32s)
        for i in 0..3 {
            let val = u32::from_le_bytes([
                self.nonce[i * 4],
                self.nonce[i * 4 + 1],
                self.nonce[i * 4 + 2],
                self.nonce[i * 4 + 3],
            ]);
            channel.mix_u64(val as u64);
        }
        // Mix counter
        channel.mix_u64(self.counter as u64);
        // Mix plaintext hash (as 8 u32s)
        for i in 0..8 {
            let val = u32::from_le_bytes([
                self.plaintext_hash[i * 4],
                self.plaintext_hash[i * 4 + 1],
                self.plaintext_hash[i * 4 + 2],
                self.plaintext_hash[i * 4 + 3],
            ]);
            channel.mix_u64(val as u64);
        }
        // Mix ciphertext hash (as 8 u32s)
        for i in 0..8 {
            let val = u32::from_le_bytes([
                self.ciphertext_hash[i * 4],
                self.ciphertext_hash[i * 4 + 1],
                self.ciphertext_hash[i * 4 + 2],
                self.ciphertext_hash[i * 4 + 3],
            ]);
            channel.mix_u64(val as u64);
        }
    }
}

/// Statement for AES-CTR (before interaction).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AESCtrStatement0 {
    pub log_size: u32,
    pub key_size: AesKeySize,
    /// Public inputs bound to the proof
    pub public_inputs: AESCtrPublicInputs,
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
        self.public_inputs.mix_into(channel);
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
    nonce: &[u8; 12],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
    inputs: &[AESCtrInput],
) -> Result<AESCtrProof<MC::H>, String>
where
    SimdBackend: BackendForChannel<MC>,
{
    let public_inputs = AESCtrPublicInputs::new(nonce, counter, plaintext, ciphertext);
    prove_aes_ctr_with_inputs_internal::<MC>(log_size, AesKeySize::Aes128, config, key.as_slice(), inputs, public_inputs)
}

/// Prove AES-256-CTR with provided inputs.
pub fn prove_aes256_ctr_with_inputs<MC: MerkleChannel>(
    log_size: u32,
    config: PcsConfig,
    key: &[u8; 32],
    nonce: &[u8; 12],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
    inputs: &[AESCtrInput],
) -> Result<AESCtrProof<MC::H>, String>
where
    SimdBackend: BackendForChannel<MC>,
{
    let public_inputs = AESCtrPublicInputs::new(nonce, counter, plaintext, ciphertext);
    prove_aes_ctr_with_inputs_internal::<MC>(log_size, AesKeySize::Aes256, config, key.as_slice(), inputs, public_inputs)
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
    public_inputs: AESCtrPublicInputs,
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
    if log_size > MAX_LOG_SIZE {
        return Err(format!(
            "log_size ({}) must be <= MAX_LOG_SIZE ({})",
            log_size, MAX_LOG_SIZE
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

    // Statement0 with cryptographically bound public inputs
    let stmt0 = AESCtrStatement0 { log_size, key_size, public_inputs };
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

    // For test data, create dummy public inputs (counter 0, empty plaintext/ciphertext hashes)
    let public_inputs = AESCtrPublicInputs::new(&nonce, 0, &[], &[]);

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

    // Statement0 with cryptographically bound public inputs
    let stmt0 = AESCtrStatement0 { log_size, key_size, public_inputs };
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

/// Maximum allowed log_size to prevent excessive memory/computation during proving.
/// 24 = 16M blocks which is already very large (256MB for AES, 1GB for ChaCha).
const MAX_LOG_SIZE: u32 = 24;

/// Validate that the proof's PCS config meets minimum security requirements.
///
/// This prevents a malicious prover from using weak STARK settings to reduce soundness.
/// The verifier specifies minimum acceptable parameters; the proof must meet or exceed them.
fn validate_pcs_config(
    proof_config: &PcsConfig,
    min_config: &PcsConfig,
) -> Result<(), VerificationError> {
    // Proof of work bits: higher = more grinding work required = more secure
    if proof_config.pow_bits < min_config.pow_bits {
        return Err(VerificationError::InvalidStructure(
            format!(
                "Proof pow_bits ({}) below minimum ({})",
                proof_config.pow_bits, min_config.pow_bits
            )
        ));
    }

    // Log blowup factor: higher = larger evaluation domain = more secure
    if proof_config.fri_config.log_blowup_factor < min_config.fri_config.log_blowup_factor {
        return Err(VerificationError::InvalidStructure(
            format!(
                "Proof log_blowup_factor ({}) below minimum ({})",
                proof_config.fri_config.log_blowup_factor,
                min_config.fri_config.log_blowup_factor
            )
        ));
    }

    // Number of FRI queries: higher = more security bits
    if proof_config.fri_config.n_queries < min_config.fri_config.n_queries {
        return Err(VerificationError::InvalidStructure(
            format!(
                "Proof n_queries ({}) below minimum ({})",
                proof_config.fri_config.n_queries,
                min_config.fri_config.n_queries
            )
        ));
    }

    Ok(())
}

/// Verify AES-CTR proof with verifier-supplied public inputs and config validation.
///
/// This is the secure verification function that ensures the proof is bound to the
/// claimed public data (nonce, counter, plaintext, ciphertext) and uses acceptable
/// security parameters.
///
/// # Arguments
/// * `proof` - The proof to verify
/// * `min_config` - Minimum acceptable PCS config (rejects proofs with weaker settings)
/// * `nonce` - The 12-byte nonce the verifier claims was used
/// * `counter` - The starting counter the verifier claims was used
/// * `plaintext` - The plaintext the verifier claims corresponds to the ciphertext
/// * `ciphertext` - The ciphertext the verifier claims was encrypted
///
/// # Security
/// - The proof's PCS config is validated against min_config before any verifier state is created
/// - Public inputs are cryptographically bound to the proof via Fiat-Shamir
/// - If the verifier-supplied inputs don't match what was proven, verification fails
pub fn verify_aes_ctr_with_public_inputs<MC: MerkleChannel>(
    proof: AESCtrProof<MC::H>,
    min_config: &PcsConfig,
    nonce: &[u8; 12],
    counter: u32,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> Result<(), VerificationError> {
    // SECURITY: Validate proof's config meets minimum requirements BEFORE creating verifier state
    // This prevents a malicious prover from using weak STARK settings
    validate_pcs_config(&proof.stark_proof.config, min_config)?;

    // Verify the proof's public inputs match the verifier's claimed data
    // This ensures the proof is bound to the specific data the verifier expects
    if !proof.stmt0.public_inputs.verify(nonce, counter, plaintext, ciphertext) {
        // Public inputs don't match - the proof is for different data
        return Err(VerificationError::OodsNotMatching);
    }

    // Proceed with STARK verification (the channel will mix the same values)
    verify_aes_ctr_internal::<MC>(proof)
}

/// Verify AES-CTR proof with config validation but without external public input validation.
///
/// WARNING: This function trusts the public inputs embedded in the proof.
/// For production use with untrusted provers, use `verify_aes_ctr_with_public_inputs` instead.
///
/// # Arguments
/// * `proof` - The proof to verify
/// * `min_config` - Minimum acceptable PCS config (rejects proofs with weaker settings)
pub fn verify_aes_ctr<MC: MerkleChannel>(
    proof: AESCtrProof<MC::H>,
    min_config: &PcsConfig,
) -> Result<(), VerificationError> {
    // SECURITY: Validate proof's config meets minimum requirements BEFORE creating verifier state
    validate_pcs_config(&proof.stark_proof.config, min_config)?;

    verify_aes_ctr_internal::<MC>(proof)
}

/// Internal verification function.
fn verify_aes_ctr_internal<MC: MerkleChannel>(
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
        verify_aes_ctr::<Blake2sMerkleChannel>(proof, &PcsConfig::default()).unwrap();
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
        verify_aes_ctr::<Blake2sMerkleChannel>(proof, &PcsConfig::default()).unwrap();
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
        let result = prove_aes128_ctr_with_inputs::<Blake2sMerkleChannel>(
            log_size, config, &key, &nonce, counter, &plaintext, &ciphertext, &[input]
        );

        match result {
            Ok(proof) => {
                println!("Proof generated successfully");
                verify_aes_ctr::<Blake2sMerkleChannel>(proof, &PcsConfig::default()).unwrap();
                println!("Verification passed!");
            }
            Err(e) => {
                panic!("Proof generation failed: {}", e);
            }
        }
    }

    // ==================== SECURITY TESTS ====================
    // These tests verify the cryptographic binding of public inputs to proofs.
    // See README.md "Security Model" section for detailed documentation.

    /// Security test: Verify that tampering with public inputs in a serialized proof
    /// causes verification to fail.
    ///
    /// Attack scenario:
    /// 1. Attacker generates valid proof for data_A
    /// 2. Attacker modifies proof.stmt0.public_inputs to claim data_B
    /// 3. Verifier should reject the tampered proof
    #[test]
    fn test_security_aes_tampered_public_inputs_in_proof() {
        use std::simd::Simd;
        use crate::aes::aes128_ctr_block;
        use crate::aes::lookup::gen_ctr::AESCtrInput;

        let key: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let nonce: [u8; 12] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let counter: u32 = 1;
        let log_size = 8;
        let config = PcsConfig::default();

        // Real plaintext and ciphertext
        let plaintext: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
        let ciphertext = aes128_ctr_block(&key, &nonce, counter, &plaintext);

        // Build valid input
        let counters = Simd::from_array(std::array::from_fn(|lane| counter + lane as u32));
        let plaintext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                if lane == 0 { plaintext[byte_idx] } else { 0 }
            }))
        });
        let padding_keystreams: Vec<[u8; 16]> = (1..16)
            .map(|lane| aes128_ctr_block(&key, &nonce, counter + lane as u32, &[0u8; 16]))
            .collect();
        let ciphertext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                if lane == 0 { ciphertext[byte_idx] } else { padding_keystreams[lane - 1][byte_idx] }
            }))
        });
        let input = AESCtrInput { nonce, counters, plaintext: plaintext_simd, ciphertext: ciphertext_simd };

        // Generate valid proof
        let mut proof = prove_aes128_ctr_with_inputs::<Blake2sMerkleChannel>(
            log_size, config, &key, &nonce, counter, &plaintext, &ciphertext, &[input]
        ).expect("Valid proof should succeed");

        // Tamper with public inputs - claim different plaintext
        let fake_plaintext: [u8; 16] = [0xff; 16];
        proof.stmt0.public_inputs = AESCtrPublicInputs::new(&nonce, counter, &fake_plaintext, &ciphertext);

        // Verification should fail - the hash comparison catches the tampering
        let result = verify_aes_ctr_with_public_inputs::<Blake2sMerkleChannel>(
            proof.clone(), &PcsConfig::default(), &nonce, counter, &fake_plaintext, &ciphertext
        );
        // This fails because the proof's Fiat-Shamir transcript used the original plaintext hash,
        // so even though we tampered with stmt0.public_inputs, the STARK verification fails
        // because challenges are derived from a different transcript.
        //
        // Note: If we pass the REAL plaintext to verify_with_public_inputs, the hash check
        // catches it immediately (fast-fail). If we pass the FAKE plaintext, the hash check
        // passes but STARK verification fails.
        assert!(result.is_err(), "Tampered proof should fail verification");
        println!("Security test passed: tampered public inputs detected");
    }

    /// Security test: Verify that a valid proof fails when verifier supplies
    /// different public inputs than what was proven.
    ///
    /// This tests the verify_*_with_public_inputs API which is the secure
    /// verification path for production use.
    #[test]
    fn test_security_aes_verify_with_wrong_public_inputs() {
        use std::simd::Simd;
        use crate::aes::aes128_ctr_block;
        use crate::aes::lookup::gen_ctr::AESCtrInput;

        let key: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let nonce: [u8; 12] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let counter: u32 = 1;
        let log_size = 8;
        let config = PcsConfig::default();

        let plaintext: [u8; 16] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
        let ciphertext = aes128_ctr_block(&key, &nonce, counter, &plaintext);

        // Build valid input
        let counters = Simd::from_array(std::array::from_fn(|lane| counter + lane as u32));
        let plaintext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                if lane == 0 { plaintext[byte_idx] } else { 0 }
            }))
        });
        let padding_keystreams: Vec<[u8; 16]> = (1..16)
            .map(|lane| aes128_ctr_block(&key, &nonce, counter + lane as u32, &[0u8; 16]))
            .collect();
        let ciphertext_simd: [Simd<u8, 16>; 16] = std::array::from_fn(|byte_idx| {
            Simd::from_array(std::array::from_fn(|lane| {
                if lane == 0 { ciphertext[byte_idx] } else { padding_keystreams[lane - 1][byte_idx] }
            }))
        });
        let input = AESCtrInput { nonce, counters, plaintext: plaintext_simd, ciphertext: ciphertext_simd };

        // Generate valid proof
        let proof = prove_aes128_ctr_with_inputs::<Blake2sMerkleChannel>(
            log_size, config, &key, &nonce, counter, &plaintext, &ciphertext, &[input]
        ).expect("Valid proof should succeed");

        // Verify with correct inputs should succeed
        assert!(
            verify_aes_ctr_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &PcsConfig::default(), &nonce, counter, &plaintext, &ciphertext
            ).is_ok(),
            "Verification with correct inputs should succeed"
        );

        // Verify with wrong plaintext should fail (fast-fail on hash check)
        let wrong_plaintext: [u8; 16] = [0xff; 16];
        assert!(
            verify_aes_ctr_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &PcsConfig::default(), &nonce, counter, &wrong_plaintext, &ciphertext
            ).is_err(),
            "Verification with wrong plaintext should fail"
        );

        // Verify with wrong nonce should fail
        let wrong_nonce: [u8; 12] = [0xff; 12];
        assert!(
            verify_aes_ctr_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &PcsConfig::default(), &wrong_nonce, counter, &plaintext, &ciphertext
            ).is_err(),
            "Verification with wrong nonce should fail"
        );

        // Verify with wrong counter should fail
        assert!(
            verify_aes_ctr_with_public_inputs::<Blake2sMerkleChannel>(
                proof.clone(), &PcsConfig::default(), &nonce, counter + 1, &plaintext, &ciphertext
            ).is_err(),
            "Verification with wrong counter should fail"
        );

        // Verify with wrong ciphertext should fail
        let wrong_ciphertext: [u8; 16] = [0xff; 16];
        assert!(
            verify_aes_ctr_with_public_inputs::<Blake2sMerkleChannel>(
                proof, &PcsConfig::default(), &nonce, counter, &plaintext, &wrong_ciphertext
            ).is_err(),
            "Verification with wrong ciphertext should fail"
        );

        println!("Security test passed: wrong public inputs correctly rejected");
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
            verify_aes_ctr::<Blake2sMerkleChannel>(proof, &PcsConfig::default()).unwrap();
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
            verify_aes_ctr::<Blake2sMerkleChannel>(proof, &PcsConfig::default()).unwrap();
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
