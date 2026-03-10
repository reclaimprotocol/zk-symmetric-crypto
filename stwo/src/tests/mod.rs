//! Underconstraint testing infrastructure.
//!
//! This module provides tools for detecting underconstrained circuits through:
//! - Malicious prover tests (generating invalid traces that should fail verification)
//! - Constraint mutation testing (verifying each constraint is necessary)
//! - Differential testing (comparing circuit outputs against native implementations)

pub mod underconstraint;
