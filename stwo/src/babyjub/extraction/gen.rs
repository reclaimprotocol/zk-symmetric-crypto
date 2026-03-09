//! Trace generation for data extraction.
//!
//! Extracts selected bytes from plaintext into two Field256 values.

use super::{
    ExtractionOutput, ExtractionPrivateInputs, ExtractionPublicInputs,
    BYTES_PER_FIELD, MAX_EXTRACT_BYTES, TOTAL_PLAINTEXT_BYTES,
};
use crate::babyjub::field256::gen::BigInt256;
use crate::babyjub::field256::N_LIMBS;

/// Trace generator for data extraction.
pub struct ExtractionTraceGen {
    pub trace: Vec<Vec<u32>>,
    pub col_index: usize,
}

impl ExtractionTraceGen {
    /// Create new trace generator.
    pub fn new() -> Self {
        Self {
            trace: Vec::new(),
            col_index: 0,
        }
    }

    /// Append a value to trace.
    fn append(&mut self, val: u32) {
        if self.col_index >= self.trace.len() {
            self.trace.push(Vec::new());
        }
        self.trace[self.col_index].push(val);
        self.col_index += 1;
    }

    /// Append a Field256 to trace.
    fn append_field256(&mut self, val: &BigInt256) {
        for limb in &val.limbs {
            self.append(*limb);
        }
    }

    /// Generate trace for extraction.
    pub fn gen_extraction(
        &mut self,
        public: &ExtractionPublicInputs,
        private: &ExtractionPrivateInputs,
    ) -> ExtractionOutput {
        // Append expected length
        self.append(public.len);

        // Process each byte
        let mut total_selected: u32 = 0;
        let mut res1_bytes: Vec<u8> = Vec::new();
        let mut res2_bytes: Vec<u8> = Vec::new();

        for i in 0..TOTAL_PLAINTEXT_BYTES {
            let plaintext_byte = private.plaintext[i];
            let bitmask_byte = public.bitmask[i];

            // Append plaintext byte
            self.append(plaintext_byte as u32);

            // Append bitmask byte
            self.append(bitmask_byte as u32);

            // Compute and append is_set (0 or 1)
            let is_set = if bitmask_byte == 0xFF { 1u32 } else { 0u32 };
            self.append(is_set);

            // Compute and append selected value
            let selected = if is_set == 1 { plaintext_byte } else { 0 };
            self.append(selected as u32);

            // Compute use_res2 flag
            let use_res2 = if total_selected >= BYTES_PER_FIELD as u32 { 1u32 } else { 0u32 };
            self.append(use_res2);

            // Compute power of 256 for position within current result
            let pos_in_result = if use_res2 == 1 {
                total_selected - BYTES_PER_FIELD as u32
            } else {
                total_selected
            };
            // Note: power would be 256^pos, but that's huge.
            // For trace, we just track the position.
            self.append(pos_in_result);

            // Compute contributions (simplified - just track for verification)
            let contrib1 = if use_res2 == 0 && is_set == 1 { selected as u32 } else { 0 };
            let contrib2 = if use_res2 == 1 && is_set == 1 { selected as u32 } else { 0 };
            self.append(contrib1);
            self.append(contrib2);

            // Accumulate
            if is_set == 1 {
                if total_selected < BYTES_PER_FIELD as u32 {
                    res1_bytes.push(selected);
                } else {
                    res2_bytes.push(selected);
                }
                total_selected += 1;
            }
        }

        // Convert byte arrays to Field256
        let res1 = bytes_to_field256(&res1_bytes);
        let res2 = bytes_to_field256(&res2_bytes);

        // Append results
        self.append_field256(&res1);
        self.append_field256(&res2);

        ExtractionOutput {
            secret_data_0: res1,
            secret_data_1: res2,
        }
    }

    /// Generate simplified trace (just bitmask validation and results).
    pub fn gen_extraction_simple(
        &mut self,
        public: &ExtractionPublicInputs,
        private: &ExtractionPrivateInputs,
    ) -> ExtractionOutput {
        // Append expected length
        self.append(public.len);

        // Process bitmask
        let mut total_selected: u32 = 0;
        for i in 0..TOTAL_PLAINTEXT_BYTES {
            let bitmask_byte = public.bitmask[i];
            self.append(bitmask_byte as u32);

            let is_set = if bitmask_byte == 0xFF { 1u32 } else { 0u32 };
            self.append(is_set);

            if is_set == 1 {
                total_selected += 1;
            }
        }

        // Extract bytes and compute results
        let output = extract_native(public, private);

        // Append results
        self.append_field256(&output.secret_data_0);
        self.append_field256(&output.secret_data_1);

        output
    }
}

impl Default for ExtractionTraceGen {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert byte array to Field256 (little-endian).
pub fn bytes_to_field256(bytes: &[u8]) -> BigInt256 {
    let mut result = BigInt256::zero();

    // Pack bytes into limbs (29 bits per limb)
    let mut bit_buffer: u64 = 0;
    let mut buffer_bits: u32 = 0;
    let mut limb_idx: usize = 0;

    for &byte in bytes {
        bit_buffer |= (byte as u64) << buffer_bits;
        buffer_bits += 8;

        while buffer_bits >= 29 && limb_idx < N_LIMBS {
            result.limbs[limb_idx] = (bit_buffer & 0x1FFFFFFF) as u32;
            bit_buffer >>= 29;
            buffer_bits -= 29;
            limb_idx += 1;
        }
    }

    // Handle remaining bits
    if buffer_bits > 0 && limb_idx < N_LIMBS {
        result.limbs[limb_idx] = (bit_buffer & 0x1FFFFFFF) as u32;
    }

    result
}

/// Convert Field256 to bytes (little-endian).
pub fn field256_to_bytes(field: &BigInt256, num_bytes: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(num_bytes);

    let mut bit_buffer: u64 = 0;
    let mut buffer_bits: u32 = 0;
    let mut limb_idx: usize = 0;

    while result.len() < num_bytes {
        // Fill buffer from limbs
        while buffer_bits < 8 && limb_idx < N_LIMBS {
            bit_buffer |= (field.limbs[limb_idx] as u64) << buffer_bits;
            buffer_bits += 29;
            limb_idx += 1;
        }

        // Extract byte
        result.push((bit_buffer & 0xFF) as u8);
        bit_buffer >>= 8;
        buffer_bits = buffer_bits.saturating_sub(8);
    }

    result
}

/// Native extraction (no trace generation).
pub fn extract_native(
    public: &ExtractionPublicInputs,
    private: &ExtractionPrivateInputs,
) -> ExtractionOutput {
    let mut res1_bytes: Vec<u8> = Vec::new();
    let mut res2_bytes: Vec<u8> = Vec::new();

    for i in 0..TOTAL_PLAINTEXT_BYTES {
        if public.bitmask[i] == 0xFF {
            if res1_bytes.len() < BYTES_PER_FIELD {
                res1_bytes.push(private.plaintext[i]);
            } else if res2_bytes.len() < BYTES_PER_FIELD {
                res2_bytes.push(private.plaintext[i]);
            }
            // Ignore bytes beyond 62
        }
    }

    ExtractionOutput {
        secret_data_0: bytes_to_field256(&res1_bytes),
        secret_data_1: bytes_to_field256(&res2_bytes),
    }
}

/// Validate extraction inputs.
pub fn validate_extraction_inputs(
    public: &ExtractionPublicInputs,
) -> Result<(), &'static str> {
    // Count selected bytes
    let count = public.bitmask.iter().filter(|&&b| b == 0xFF).count();

    // Check all bitmask bytes are valid
    for &b in &public.bitmask {
        if b != 0x00 && b != 0xFF {
            return Err("Invalid bitmask byte (must be 0x00 or 0xFF)");
        }
    }

    // Check count matches expected
    if count != public.len as usize {
        return Err("Bitmask count doesn't match expected length");
    }

    // Check not exceeding max
    if count > MAX_EXTRACT_BYTES {
        return Err("Too many bytes selected (max 62)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_field256_roundtrip() {
        let original_bytes: Vec<u8> = (0..31).collect();
        let field = bytes_to_field256(&original_bytes);
        let recovered = field256_to_bytes(&field, 31);

        assert_eq!(original_bytes, recovered);
    }

    #[test]
    fn test_extract_native() {
        let mut public = ExtractionPublicInputs::default();
        let mut private = ExtractionPrivateInputs::default();

        // Select first 10 bytes
        for i in 0..10 {
            public.bitmask[i] = 0xFF;
            private.plaintext[i] = (i + 1) as u8;
        }
        public.len = 10;

        let output = extract_native(&public, &private);

        // Convert back to bytes
        let bytes = field256_to_bytes(&output.secret_data_0, 10);
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_extract_two_fields() {
        let mut public = ExtractionPublicInputs::default();
        let mut private = ExtractionPrivateInputs::default();

        // Select 62 bytes (max)
        for i in 0..62 {
            public.bitmask[i] = 0xFF;
            private.plaintext[i] = (i + 1) as u8;
        }
        public.len = 62;

        let output = extract_native(&public, &private);

        // First 31 bytes in secret_data_0
        let bytes0 = field256_to_bytes(&output.secret_data_0, 31);
        assert_eq!(bytes0[0], 1);
        assert_eq!(bytes0[30], 31);

        // Next 31 bytes in secret_data_1
        let bytes1 = field256_to_bytes(&output.secret_data_1, 31);
        assert_eq!(bytes1[0], 32);
        assert_eq!(bytes1[30], 62);
    }

    #[test]
    fn test_extract_non_contiguous() {
        let mut public = ExtractionPublicInputs::default();
        let mut private = ExtractionPrivateInputs::default();

        // Select bytes at positions 0, 10, 20
        public.bitmask[0] = 0xFF;
        public.bitmask[10] = 0xFF;
        public.bitmask[20] = 0xFF;
        private.plaintext[0] = 0xAA;
        private.plaintext[10] = 0xBB;
        private.plaintext[20] = 0xCC;
        public.len = 3;

        let output = extract_native(&public, &private);

        let bytes = field256_to_bytes(&output.secret_data_0, 3);
        assert_eq!(bytes, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_validate_inputs() {
        let mut public = ExtractionPublicInputs::default();
        public.bitmask[0] = 0xFF;
        public.len = 1;

        assert!(validate_extraction_inputs(&public).is_ok());

        // Wrong length
        public.len = 2;
        assert!(validate_extraction_inputs(&public).is_err());

        // Invalid bitmask value
        public.len = 2;
        public.bitmask[1] = 0x80; // Invalid
        assert!(validate_extraction_inputs(&public).is_err());
    }

    #[test]
    fn test_trace_gen() {
        let mut public = ExtractionPublicInputs::default();
        let mut private = ExtractionPrivateInputs::default();

        for i in 0..5 {
            public.bitmask[i] = 0xFF;
            private.plaintext[i] = (i * 10) as u8;
        }
        public.len = 5;

        let mut gen = ExtractionTraceGen::new();
        let output = gen.gen_extraction_simple(&public, &private);

        // Verify output matches native
        let native_output = extract_native(&public, &private);
        assert_eq!(output.secret_data_0.limbs, native_output.secret_data_0.limbs);
    }
}
