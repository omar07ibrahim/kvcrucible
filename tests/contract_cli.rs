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
        "status": "contract-first prototype; no engine adapter is implemented yet",
        "trace_format": "kvcrucible.trace/v1alpha1",
        "guarantees": [
            "publisher-local cursor and epoch accounting",
            "explicit exact, recovering, and unknown consumer states",
            "deterministic fault replay from a canonical trace",
            "convergence checks against a pristine reference execution",
            "deterministic 1-minimal witnesses for failed checks"
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
