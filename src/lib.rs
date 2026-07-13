//! Public contract for `KVCrucible`.
//!
//! The crate exposes the reviewed scope contract, typed trace IR, bounded
//! canonical JSONL ingestion, and incremental trace validation. State folding
//! and replay remain later layers.

use serde::Serialize;

pub mod codec;
pub mod ir;
pub mod jsonl;
pub mod limits;
pub mod trace;

/// Canonical trace format targeted by the first release.
pub const TRACE_FORMAT_VERSION: &str = "kvcrucible.trace/v1alpha1";

const GUARANTEES: [&str; 5] = [
    "publisher-local cursor and epoch accounting",
    "explicit exact, recovering, and unknown consumer states",
    "deterministic fault replay from a canonical trace",
    "convergence checks against a pristine reference execution",
    "deterministic 1-minimal witnesses for failed checks",
];

const NON_GOALS: [&str; 5] = [
    "proving a serving engine correct",
    "inspecting GPU KV tensors",
    "inferring allocator or reference-count state from cache events",
    "optimizing scheduling or routing policies",
    "repairing a production cache automatically",
];

/// A machine-readable statement of what the current project intends to check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Contract {
    /// Project name used in reports.
    pub project: &'static str,
    /// Honest implementation status.
    pub status: &'static str,
    /// Versioned trace format under design.
    pub trace_format: &'static str,
    /// Properties in scope for the first release.
    pub guarantees: &'static [&'static str],
    /// Claims the project explicitly does not make.
    pub non_goals: &'static [&'static str],
}

impl Contract {
    /// Return the v0.1 scope contract.
    #[must_use]
    pub const fn v0_1() -> Self {
        Self {
            project: "KVCrucible",
            status: "contract-first prototype; no engine adapter is implemented yet",
            trace_format: TRACE_FORMAT_VERSION,
            guarantees: &GUARANTEES,
            non_goals: &NON_GOALS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Contract, TRACE_FORMAT_VERSION};

    #[test]
    fn contract_is_explicit_about_its_boundary() {
        let contract = Contract::v0_1();

        assert_eq!(contract.trace_format, TRACE_FORMAT_VERSION);
        assert!(contract.status.contains("no engine adapter"));
        assert!(
            contract
                .non_goals
                .contains(&"proving a serving engine correct")
        );
    }

    #[test]
    fn contract_serializes_deterministically() {
        let first = serde_json::to_string_pretty(&Contract::v0_1()).unwrap();
        let second = serde_json::to_string_pretty(&Contract::v0_1()).unwrap();

        assert_eq!(first, second);
        assert!(first.contains(TRACE_FORMAT_VERSION));
    }
}
