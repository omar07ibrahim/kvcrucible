use std::process::Command;

use serde_json::json;

#[test]
fn json_contract_is_a_stable_cli_boundary() {
    let output = Command::new(env!("CARGO_BIN_EXE_kvcrucible"))
        .args(["contract", "--format", "json"])
        .output()
        .expect("contract command should start");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let actual: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("contract output should be JSON");
    let expected = json!({
        "project": "KVCrucible",
        "status": "fault materialization and eligibility-aware convergence implemented; replay orchestration, reduction, reports, and engine adapter pending",
        "trace_format": "kvcrucible.trace/v1alpha1",
        "implemented_capabilities": [
            "bounded canonical JSONL ingestion and structural validation",
            "internal session-bounded semantic envelope fingerprints",
            "publisher-local cursor and epoch accounting",
            "bounded exact, recovering, and unknown delivered-envelope states",
            "atomic scoped cache-view projection with modeled gap exhaustion",
            "coordinated EOF sealing with opaque numeric fault plans",
            "deterministic bounded drop, duplicate, and reorder materialization",
            "schedule-prefix pristine/faulted execution with eligibility-aware per-stream convergence"
        ],
        "planned_v0_1_capabilities": [
            "bounded replay request, outcome, response-attribution, and expiry orchestration",
            "deterministic 1-minimal witnesses for failed checks",
            "stable reports and one pinned vLLM adapter"
        ],
        "non_goals": [
            "proving a serving engine correct",
            "inspecting GPU KV tensors",
            "inferring allocator or reference-count state from cache events",
            "optimizing scheduling or routing policies",
            "repairing a production cache automatically"
        ]
    });

    assert_eq!(actual, expected);
}
