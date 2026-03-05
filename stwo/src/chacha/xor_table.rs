//! XOR lookup table infrastructure for ChaCha20.
//!
//! ChaCha requires XOR tables at widths: 4, 7, 8, 9, 12 bits.
//! This is identical to BLAKE's requirements.

use std::simd::u32x16;

use itertools::Itertools;
use num_traits::Zero;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{PackedBaseField, LOG_N_LANES};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, InfoEvaluator, LogupTraceGenerator, Relation,
    RelationEntry,
};

use super::constraints::{XorElements12, XorElements4, XorElements7, XorElements8, XorElements9};

/// Describes an XOR table with n_bits elements and n_expand_bits optimization.
#[derive(Debug, Clone, Copy)]
pub struct XorTable {
    pub n_bits: u32,
    pub n_expand_bits: u32,
    pub index_in_table: usize,
}

impl XorTable {
    pub const fn new(n_bits: u32, n_expand_bits: u32, index_in_table: usize) -> Self {
        Self {
            n_bits,
            n_expand_bits,
            index_in_table,
        }
    }

    pub fn id(&self) -> PreProcessedColumnId {
        PreProcessedColumnId {
            id: format!(
                "preprocessed_xor_table_{}_{}_{}",
                self.n_bits, self.n_expand_bits, self.index_in_table
            ),
        }
    }

    pub const fn limb_bits(&self) -> u32 {
        self.n_bits - self.n_expand_bits
    }

    pub const fn column_bits(&self) -> u32 {
        2 * self.limb_bits()
    }

    /// Generate the preprocessed (constant) trace for XOR table.
    pub fn generate_constant_trace(
        &self,
    ) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
        let limb_bits = self.limb_bits();

        let a_col: BaseColumn = (0..(1 << self.column_bits()))
            .map(|i| BaseField::from_u32_unchecked((i >> limb_bits) as u32))
            .collect();
        let b_col: BaseColumn = (0..(1 << self.column_bits()))
            .map(|i| BaseField::from_u32_unchecked((i & ((1 << limb_bits) - 1)) as u32))
            .collect();
        let c_col: BaseColumn = (0..(1 << self.column_bits()))
            .map(|i| {
                BaseField::from_u32_unchecked(
                    ((i >> limb_bits) ^ (i & ((1 << limb_bits) - 1))) as u32,
                )
            })
            .collect();

        [a_col, b_col, c_col]
            .map(|x| CircleEvaluation::new(CanonicCoset::new(self.column_bits()).circle_domain(), x))
            .to_vec()
    }
}

/// Accumulator that tracks XOR lookup multiplicities.
pub struct XorAccumulator {
    pub n_bits: u32,
    pub n_expand_bits: u32,
    /// Multiplicity columns: 2^(2*n_expand_bits) columns.
    pub mults: Vec<BaseColumn>,
}

impl XorAccumulator {
    pub fn new(n_bits: u32, n_expand_bits: u32) -> Self {
        let table = XorTable::new(n_bits, n_expand_bits, 0);
        let n_columns = 1 << (2 * n_expand_bits);
        Self {
            n_bits,
            n_expand_bits,
            mults: (0..n_columns)
                .map(|_| BaseColumn::zeros(1 << table.column_bits()))
                .collect_vec(),
        }
    }

    /// Add an XOR lookup to the accumulator.
    pub fn add_input(&mut self, a: u32x16, b: u32x16) {
        let limb_bits = self.n_bits - self.n_expand_bits;

        // Split a and b into high and low parts
        let al = a & u32x16::splat((1 << limb_bits) - 1);
        let ah = a >> limb_bits;
        let bl = b & u32x16::splat((1 << limb_bits) - 1);
        let bh = b >> limb_bits;

        // Column index = (ah, bh) pair
        let column_idx = (ah << self.n_expand_bits) + bh;
        // Row index = (al, bl) pair
        let offset = (al << limb_bits) + bl;

        // Loop over packed values and increment multiplicities
        for (column_idx, offset) in column_idx.as_array().iter().zip(offset.as_array().iter()) {
            self.mults[*column_idx as usize].as_mut_slice()[*offset as usize].0 += 1;
        }
    }
}

/// Collection of XOR accumulators for all widths needed by ChaCha.
#[derive(Default)]
pub struct XorAccums {
    pub xor12: Option<XorAccumulator>,
    pub xor9: Option<XorAccumulator>,
    pub xor8: Option<XorAccumulator>,
    pub xor7: Option<XorAccumulator>,
    pub xor4: Option<XorAccumulator>,
}

impl XorAccums {
    pub fn new() -> Self {
        Self {
            xor12: Some(XorAccumulator::new(12, 4)),
            xor9: Some(XorAccumulator::new(9, 2)),
            xor8: Some(XorAccumulator::new(8, 2)),
            xor7: Some(XorAccumulator::new(7, 2)),
            xor4: Some(XorAccumulator::new(4, 0)),
        }
    }

    /// Add an XOR input to the appropriate accumulator based on width.
    pub fn add_input(&mut self, w: u32, a: u32x16, b: u32x16) {
        match w {
            12 => self.xor12.as_mut().unwrap().add_input(a, b),
            9 => self.xor9.as_mut().unwrap().add_input(a, b),
            8 => self.xor8.as_mut().unwrap().add_input(a, b),
            7 => self.xor7.as_mut().unwrap().add_input(a, b),
            4 => self.xor4.as_mut().unwrap().add_input(a, b),
            _ => panic!("Invalid XOR width: {}", w),
        }
    }
}

// =============================================================================
// XOR Table Module: xor12
// =============================================================================
pub mod xor12 {
    use super::*;

    pub const ELEM_BITS: u32 = 12;
    pub const EXPAND_BITS: u32 = 4;

    pub type XorTableComponent = FrameworkComponent<XorTableEval>;

    pub fn trace_sizes() -> TreeVec<Vec<u32>> {
        let component = XorTableEval {
            lookup_elements: XorElements12::dummy(),
            claimed_sum: SecureField::zero(),
        };
        let info = component.evaluate(InfoEvaluator::empty());
        info.mask_offsets
            .as_cols_ref()
            .map_cols(|_| XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
    }

    pub struct XorTableEval {
        pub lookup_elements: XorElements12,
        pub claimed_sum: SecureField,
    }

    impl FrameworkEval for XorTableEval {
        fn log_size(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits()
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits() + 1
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let al = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).id());
            let bl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 1).id());
            let cl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 2).id());

            let limb_bits = XorTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits();

            for i in 0..(1 << (2 * EXPAND_BITS)) {
                let (ih, jh) = ((i >> EXPAND_BITS) as u32, (i % (1 << EXPAND_BITS)) as u32);
                let multiplicity = eval.next_trace_mask();

                let a = al.clone()
                    + E::F::from(BaseField::from_u32_unchecked(ih << limb_bits));
                let b = bl.clone()
                    + E::F::from(BaseField::from_u32_unchecked(jh << limb_bits));
                let c = cl.clone()
                    + E::F::from(BaseField::from_u32_unchecked((ih ^ jh) << limb_bits));

                eval.add_to_relation(RelationEntry::new(
                    &self.lookup_elements,
                    -E::EF::from(multiplicity),
                    &[a, b, c],
                ));
            }

            eval.finalize_logup_in_pairs();
            eval
        }
    }

    pub struct XorTableLookupData {
        pub xor_accum: XorAccumulator,
    }

    pub fn generate_trace(
        xor_accum: XorAccumulator,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        XorTableLookupData,
    ) {
        (
            xor_accum
                .mults
                .iter()
                .map(|mult| {
                    CircleEvaluation::new(
                        CanonicCoset::new(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
                            .circle_domain(),
                        mult.clone(),
                    )
                })
                .collect_vec(),
            XorTableLookupData { xor_accum },
        )
    }

    pub fn generate_interaction_trace(
        lookup_data: XorTableLookupData,
        lookup_elements: &XorElements12,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        generate_xor_interaction_trace_impl(
            lookup_data.xor_accum,
            ELEM_BITS,
            EXPAND_BITS,
            lookup_elements,
        )
    }
}

// =============================================================================
// XOR Table Module: xor9
// =============================================================================
pub mod xor9 {
    use super::*;

    pub const ELEM_BITS: u32 = 9;
    pub const EXPAND_BITS: u32 = 2;

    pub type XorTableComponent = FrameworkComponent<XorTableEval>;

    pub fn trace_sizes() -> TreeVec<Vec<u32>> {
        let component = XorTableEval {
            lookup_elements: XorElements9::dummy(),
            claimed_sum: SecureField::zero(),
        };
        let info = component.evaluate(InfoEvaluator::empty());
        info.mask_offsets
            .as_cols_ref()
            .map_cols(|_| XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
    }

    pub struct XorTableEval {
        pub lookup_elements: XorElements9,
        pub claimed_sum: SecureField,
    }

    impl FrameworkEval for XorTableEval {
        fn log_size(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits()
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits() + 1
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let al = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).id());
            let bl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 1).id());
            let cl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 2).id());

            let limb_bits = XorTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits();

            for i in 0..(1 << (2 * EXPAND_BITS)) {
                let (ih, jh) = ((i >> EXPAND_BITS) as u32, (i % (1 << EXPAND_BITS)) as u32);
                let multiplicity = eval.next_trace_mask();

                let a = al.clone()
                    + E::F::from(BaseField::from_u32_unchecked(ih << limb_bits));
                let b = bl.clone()
                    + E::F::from(BaseField::from_u32_unchecked(jh << limb_bits));
                let c = cl.clone()
                    + E::F::from(BaseField::from_u32_unchecked((ih ^ jh) << limb_bits));

                eval.add_to_relation(RelationEntry::new(
                    &self.lookup_elements,
                    -E::EF::from(multiplicity),
                    &[a, b, c],
                ));
            }

            eval.finalize_logup_in_pairs();
            eval
        }
    }

    pub struct XorTableLookupData {
        pub xor_accum: XorAccumulator,
    }

    pub fn generate_trace(
        xor_accum: XorAccumulator,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        XorTableLookupData,
    ) {
        (
            xor_accum
                .mults
                .iter()
                .map(|mult| {
                    CircleEvaluation::new(
                        CanonicCoset::new(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
                            .circle_domain(),
                        mult.clone(),
                    )
                })
                .collect_vec(),
            XorTableLookupData { xor_accum },
        )
    }

    pub fn generate_interaction_trace(
        lookup_data: XorTableLookupData,
        lookup_elements: &XorElements9,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        generate_xor_interaction_trace_impl(
            lookup_data.xor_accum,
            ELEM_BITS,
            EXPAND_BITS,
            lookup_elements,
        )
    }
}

// =============================================================================
// XOR Table Module: xor8
// =============================================================================
pub mod xor8 {
    use super::*;

    pub const ELEM_BITS: u32 = 8;
    pub const EXPAND_BITS: u32 = 2;

    pub type XorTableComponent = FrameworkComponent<XorTableEval>;

    pub fn trace_sizes() -> TreeVec<Vec<u32>> {
        let component = XorTableEval {
            lookup_elements: XorElements8::dummy(),
            claimed_sum: SecureField::zero(),
        };
        let info = component.evaluate(InfoEvaluator::empty());
        info.mask_offsets
            .as_cols_ref()
            .map_cols(|_| XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
    }

    pub struct XorTableEval {
        pub lookup_elements: XorElements8,
        pub claimed_sum: SecureField,
    }

    impl FrameworkEval for XorTableEval {
        fn log_size(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits()
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits() + 1
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let al = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).id());
            let bl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 1).id());
            let cl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 2).id());

            let limb_bits = XorTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits();

            for i in 0..(1 << (2 * EXPAND_BITS)) {
                let (ih, jh) = ((i >> EXPAND_BITS) as u32, (i % (1 << EXPAND_BITS)) as u32);
                let multiplicity = eval.next_trace_mask();

                let a = al.clone()
                    + E::F::from(BaseField::from_u32_unchecked(ih << limb_bits));
                let b = bl.clone()
                    + E::F::from(BaseField::from_u32_unchecked(jh << limb_bits));
                let c = cl.clone()
                    + E::F::from(BaseField::from_u32_unchecked((ih ^ jh) << limb_bits));

                eval.add_to_relation(RelationEntry::new(
                    &self.lookup_elements,
                    -E::EF::from(multiplicity),
                    &[a, b, c],
                ));
            }

            eval.finalize_logup_in_pairs();
            eval
        }
    }

    pub struct XorTableLookupData {
        pub xor_accum: XorAccumulator,
    }

    pub fn generate_trace(
        xor_accum: XorAccumulator,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        XorTableLookupData,
    ) {
        (
            xor_accum
                .mults
                .iter()
                .map(|mult| {
                    CircleEvaluation::new(
                        CanonicCoset::new(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
                            .circle_domain(),
                        mult.clone(),
                    )
                })
                .collect_vec(),
            XorTableLookupData { xor_accum },
        )
    }

    pub fn generate_interaction_trace(
        lookup_data: XorTableLookupData,
        lookup_elements: &XorElements8,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        generate_xor_interaction_trace_impl(
            lookup_data.xor_accum,
            ELEM_BITS,
            EXPAND_BITS,
            lookup_elements,
        )
    }
}

// =============================================================================
// XOR Table Module: xor7
// =============================================================================
pub mod xor7 {
    use super::*;

    pub const ELEM_BITS: u32 = 7;
    pub const EXPAND_BITS: u32 = 2;

    pub type XorTableComponent = FrameworkComponent<XorTableEval>;

    pub fn trace_sizes() -> TreeVec<Vec<u32>> {
        let component = XorTableEval {
            lookup_elements: XorElements7::dummy(),
            claimed_sum: SecureField::zero(),
        };
        let info = component.evaluate(InfoEvaluator::empty());
        info.mask_offsets
            .as_cols_ref()
            .map_cols(|_| XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
    }

    pub struct XorTableEval {
        pub lookup_elements: XorElements7,
        pub claimed_sum: SecureField,
    }

    impl FrameworkEval for XorTableEval {
        fn log_size(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits()
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits() + 1
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let al = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).id());
            let bl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 1).id());
            let cl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 2).id());

            let limb_bits = XorTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits();

            for i in 0..(1 << (2 * EXPAND_BITS)) {
                let (ih, jh) = ((i >> EXPAND_BITS) as u32, (i % (1 << EXPAND_BITS)) as u32);
                let multiplicity = eval.next_trace_mask();

                let a = al.clone()
                    + E::F::from(BaseField::from_u32_unchecked(ih << limb_bits));
                let b = bl.clone()
                    + E::F::from(BaseField::from_u32_unchecked(jh << limb_bits));
                let c = cl.clone()
                    + E::F::from(BaseField::from_u32_unchecked((ih ^ jh) << limb_bits));

                eval.add_to_relation(RelationEntry::new(
                    &self.lookup_elements,
                    -E::EF::from(multiplicity),
                    &[a, b, c],
                ));
            }

            eval.finalize_logup_in_pairs();
            eval
        }
    }

    pub struct XorTableLookupData {
        pub xor_accum: XorAccumulator,
    }

    pub fn generate_trace(
        xor_accum: XorAccumulator,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        XorTableLookupData,
    ) {
        (
            xor_accum
                .mults
                .iter()
                .map(|mult| {
                    CircleEvaluation::new(
                        CanonicCoset::new(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
                            .circle_domain(),
                        mult.clone(),
                    )
                })
                .collect_vec(),
            XorTableLookupData { xor_accum },
        )
    }

    pub fn generate_interaction_trace(
        lookup_data: XorTableLookupData,
        lookup_elements: &XorElements7,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        generate_xor_interaction_trace_impl(
            lookup_data.xor_accum,
            ELEM_BITS,
            EXPAND_BITS,
            lookup_elements,
        )
    }
}

// =============================================================================
// XOR Table Module: xor4
// =============================================================================
pub mod xor4 {
    use super::*;

    pub const ELEM_BITS: u32 = 4;
    pub const EXPAND_BITS: u32 = 0;

    pub type XorTableComponent = FrameworkComponent<XorTableEval>;

    pub fn trace_sizes() -> TreeVec<Vec<u32>> {
        let component = XorTableEval {
            lookup_elements: XorElements4::dummy(),
            claimed_sum: SecureField::zero(),
        };
        let info = component.evaluate(InfoEvaluator::empty());
        info.mask_offsets
            .as_cols_ref()
            .map_cols(|_| XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
    }

    pub struct XorTableEval {
        pub lookup_elements: XorElements4,
        pub claimed_sum: SecureField,
    }

    impl FrameworkEval for XorTableEval {
        fn log_size(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits()
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits() + 1
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let al = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).id());
            let bl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 1).id());
            let cl = eval.get_preprocessed_column(XorTable::new(ELEM_BITS, EXPAND_BITS, 2).id());

            let limb_bits = XorTable::new(ELEM_BITS, EXPAND_BITS, 0).limb_bits();

            // For xor4 with EXPAND_BITS=0, we only have 1 iteration
            for i in 0..(1usize << (2 * EXPAND_BITS)).max(1) {
                let (ih, jh) = ((i >> EXPAND_BITS) as u32, (i % (1usize << EXPAND_BITS).max(1)) as u32);
                let multiplicity = eval.next_trace_mask();

                let a = al.clone()
                    + E::F::from(BaseField::from_u32_unchecked(ih << limb_bits));
                let b = bl.clone()
                    + E::F::from(BaseField::from_u32_unchecked(jh << limb_bits));
                let c = cl.clone()
                    + E::F::from(BaseField::from_u32_unchecked((ih ^ jh) << limb_bits));

                eval.add_to_relation(RelationEntry::new(
                    &self.lookup_elements,
                    -E::EF::from(multiplicity),
                    &[a, b, c],
                ));
            }

            eval.finalize_logup_in_pairs();
            eval
        }
    }

    pub struct XorTableLookupData {
        pub xor_accum: XorAccumulator,
    }

    pub fn generate_trace(
        xor_accum: XorAccumulator,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        XorTableLookupData,
    ) {
        (
            xor_accum
                .mults
                .iter()
                .map(|mult| {
                    CircleEvaluation::new(
                        CanonicCoset::new(XorTable::new(ELEM_BITS, EXPAND_BITS, 0).column_bits())
                            .circle_domain(),
                        mult.clone(),
                    )
                })
                .collect_vec(),
            XorTableLookupData { xor_accum },
        )
    }

    pub fn generate_interaction_trace(
        lookup_data: XorTableLookupData,
        lookup_elements: &XorElements4,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        generate_xor_interaction_trace_impl(
            lookup_data.xor_accum,
            ELEM_BITS,
            EXPAND_BITS,
            lookup_elements,
        )
    }
}

/// Shared implementation for XOR interaction trace generation.
fn generate_xor_interaction_trace_impl<R: Relation<PackedBaseField, PackedSecureField>>(
    xor_accum: XorAccumulator,
    elem_bits: u32,
    expand_bits: u32,
    lookup_elements: &R,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let table = XorTable::new(elem_bits, expand_bits, 0);
    let limb_bits = table.limb_bits();

    let offsets_vec = u32x16::from_array(std::array::from_fn(|i| i as u32));
    let mut logup_gen = LogupTraceGenerator::new(table.column_bits());

    // Iterate columns in pairs for efficiency
    let mut iter = xor_accum.mults.iter().enumerate().array_chunks::<2>();

    for [(i0, mults0), (i1, mults1)] in &mut iter {
        let mut col_gen = logup_gen.new_col();

        // Extract ah, bh from column index
        let ah0 = i0 as u32 >> expand_bits;
        let bh0 = i0 as u32 & ((1 << expand_bits) - 1);
        let ah1 = i1 as u32 >> expand_bits;
        let bh1 = i1 as u32 & ((1 << expand_bits) - 1);

        for vec_row in 0..(1 << (table.column_bits() - LOG_N_LANES)) {
            // Extract al, blh from vec_row
            let al = vec_row >> (limb_bits - LOG_N_LANES);
            let blh = vec_row & ((1 << (limb_bits - LOG_N_LANES)) - 1);

            // Construct a, b, c vectors
            let a0 = u32x16::splat((ah0 << limb_bits) | al);
            let a1 = u32x16::splat((ah1 << limb_bits) | al);
            let b0 = u32x16::splat((bh0 << limb_bits) | (blh << LOG_N_LANES)) | offsets_vec;
            let b1 = u32x16::splat((bh1 << limb_bits) | (blh << LOG_N_LANES)) | offsets_vec;
            let c0 = a0 ^ b0;
            let c1 = a1 ^ b1;

            let p0: PackedSecureField = lookup_elements
                .combine(&[a0, b0, c0].map(|x| unsafe { PackedBaseField::from_simd_unchecked(x) }));
            let p1: PackedSecureField = lookup_elements
                .combine(&[a1, b1, c1].map(|x| unsafe { PackedBaseField::from_simd_unchecked(x) }));

            let num = p1 * mults0.data[vec_row as usize] + p0 * mults1.data[vec_row as usize];
            let denom = p0 * p1;
            col_gen.write_frac(vec_row as usize, -num, denom);
        }
        col_gen.finalize_col();
    }

    // Handle odd remainder
    if let Some(rem) = iter.into_remainder() {
        if let Some((i, mults)) = rem.collect_vec().pop() {
            let mut col_gen = logup_gen.new_col();
            let ah = i as u32 >> expand_bits;
            let bh = i as u32 & ((1 << expand_bits) - 1);

            for vec_row in 0..(1 << (table.column_bits() - LOG_N_LANES)) {
                let al = vec_row >> (limb_bits - LOG_N_LANES);
                let a = u32x16::splat((ah << limb_bits) | al);
                let bm = vec_row & ((1 << (limb_bits - LOG_N_LANES)) - 1);
                let b = u32x16::splat((bh << limb_bits) | (bm << LOG_N_LANES)) | offsets_vec;
                let c = a ^ b;

                let p: PackedSecureField = lookup_elements
                    .combine(&[a, b, c].map(|x| unsafe { PackedBaseField::from_simd_unchecked(x) }));

                let num = mults.data[vec_row as usize];
                col_gen.write_frac(vec_row as usize, PackedSecureField::from(-num), p);
            }
            col_gen.finalize_col();
        }
    }

    logup_gen.finalize_last()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_accumulator() {
        let mut accum = XorAccumulator::new(8, 2);

        // Add some XOR lookups
        let a = u32x16::splat(0x12);
        let b = u32x16::splat(0x34);
        accum.add_input(a, b);

        // The multiplicities should be updated
        // For 8-bit with 2 expand bits: limb_bits = 6
        // a = 0x12 = 18, b = 0x34 = 52
        // ah = 18 >> 6 = 0, al = 18 & 63 = 18
        // bh = 52 >> 6 = 0, bl = 52 & 63 = 52
        // column_idx = (0 << 2) + 0 = 0
        // offset = (18 << 6) + 52 = 1204
        assert_eq!(accum.mults[0].as_slice()[1204].0, 16); // 16 lanes
    }

    #[test]
    fn test_xor_table_constant_trace() {
        let table = XorTable::new(4, 0, 0);
        let trace = table.generate_constant_trace();

        // For 4-bit XOR with 0 expand: 2^8 = 256 rows, 3 columns
        assert_eq!(trace.len(), 3);

        // Check a few values: at row i, a = i >> 4, b = i & 15, c = a ^ b
        // Row 0x35: a = 3, b = 5, c = 6
        let row = 0x35;
        assert_eq!(trace[0].at(row).0, 3); // a
        assert_eq!(trace[1].at(row).0, 5); // b
        assert_eq!(trace[2].at(row).0, 6); // c = 3 ^ 5
    }
}
