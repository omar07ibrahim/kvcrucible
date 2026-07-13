//! Public contract for `KVCrucible`.
//!
//! The crate exposes the reviewed scope contract, typed trace IR, bounded
//! canonical JSONL ingestion, incremental trace validation, internal
//! non-exported semantic fingerprinting, and a bounded per-stream
//! delivered-envelope fold. Coordinated EOF sealing now produces opaque,
//! numeric fault plans and deterministically materializes their delivery order;
//! replay orchestration, convergence, reduction, reports, and engine adapters
//! remain later layers.

use serde::Serialize;

mod fingerprint;

pub mod codec;
pub mod ir;
pub mod jsonl;
pub mod limits;
pub mod scenario;
pub mod state;
pub mod trace;

/// Canonical trace format targeted by the first release.
pub const TRACE_FORMAT_VERSION: &str = "kvcrucible.trace/v1alpha1";

const IMPLEMENTED_CAPABILITIES: [&str; 7] = [
    "bounded canonical JSONL ingestion and structural validation",
    "internal session-bounded semantic envelope fingerprints",
    "publisher-local cursor and epoch accounting",
    "bounded exact, recovering, and unknown delivered-envelope states",
    "atomic scoped cache-view projection with modeled gap exhaustion",
    "coordinated EOF sealing with opaque numeric fault plans",
    "deterministic bounded drop, duplicate, and reorder materialization",
];

const PLANNED_V0_1_CAPABILITIES: [&str; 4] = [
    "bounded replay policy over explicit observed evidence",
    "convergence checks against a pristine reference execution",
    "deterministic 1-minimal witnesses for failed checks",
    "stable reports and one pinned vLLM adapter",
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
    /// Capabilities present in the current build.
    pub implemented_capabilities: &'static [&'static str],
    /// Capabilities still planned before v0.1.
    pub planned_v0_1_capabilities: &'static [&'static str],
    /// Claims the project explicitly does not make.
    pub non_goals: &'static [&'static str],
}

impl Contract {
    /// Return the v0.1 scope contract.
    #[must_use]
    pub const fn v0_1() -> Self {
        Self {
            project: "KVCrucible",
            status: "deterministic fault materialization implemented; replay, convergence, reduction, reports, and engine adapter pending",
            trace_format: TRACE_FORMAT_VERSION,
            implemented_capabilities: &IMPLEMENTED_CAPABILITIES,
            planned_v0_1_capabilities: &PLANNED_V0_1_CAPABILITIES,
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
        assert!(contract.status.contains("materialization"));
        assert!(contract.status.contains("convergence"));
        assert!(contract.status.contains("engine adapter"));
        assert!(contract.status.contains("pending"));
        assert!(
            contract
                .implemented_capabilities
                .contains(&"bounded exact, recovering, and unknown delivered-envelope states")
        );
        assert!(
            contract
                .implemented_capabilities
                .contains(&"coordinated EOF sealing with opaque numeric fault plans")
        );
        assert!(
            contract
                .implemented_capabilities
                .contains(&"deterministic bounded drop, duplicate, and reorder materialization")
        );
        assert!(
            contract
                .planned_v0_1_capabilities
                .contains(&"convergence checks against a pristine reference execution")
        );
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
