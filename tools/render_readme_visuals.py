#!/usr/bin/env python3
"""Capture deterministic KVCrucible evidence and render README visuals."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import socket
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypedDict, cast

ROOT: Final = Path(__file__).resolve().parents[1]
OUTPUT_DIRECTORY: Final = ROOT / "docs" / "visuals" / "generated"

BACKGROUND: Final = "#07111f"
PANEL: Final = "#0f1b2d"
PANEL_ALT: Final = "#111f34"
LINE: Final = "#334155"
TEXT: Final = "#e6edf7"
MUTED: Final = "#9fb0c7"
CYAN: Final = "#5eead4"
PURPLE: Final = "#a78bfa"
GREEN: Final = "#34d399"
AMBER: Final = "#fbbf24"
RED: Final = "#fb7185"

SOURCE_PATHS: Final = (
    ".cargo/config.toml",
    ".github/workflows/ci.yml",
    "Cargo.lock",
    "Cargo.toml",
    "README.md",
    "rust-toolchain.toml",
    "tools/render_readme_visuals.py",
)

SOURCE_GLOBS: Final = (
    "docs/*.md",
    "examples/**/*.rs",
    "spec/*.md",
    "src/**/*.rs",
    "tests/**/*",
)

EXPECTED_OUTPUTS: Final = (
    "architecture.svg",
    "certainty-decision.svg",
    "evidence-summary.txt",
    "fault-timeline.svg",
    "manifest.sha256.json",
    "setup-workflow.svg",
    "terminal-evidence.svg",
    "terminal-transcript.txt",
    "verdict-matrix.svg",
    "visual-evidence.json",
)

TEST_RESULT = re.compile(
    r"test result: (?:ok|FAILED)\. "
    r"(?P<passed>\d+) passed; "
    r"(?P<failed>\d+) failed; "
    r"(?P<ignored>\d+) ignored; "
    r"(?P<measured>\d+) measured; "
    r"(?P<filtered>\d+) filtered out"
)

SENSITIVE_PATTERNS: Final = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bauthorization:\s*bearer\s+\S+"),
    re.compile(r"(?i)\b(?:api[_-]?key|secret|password)\s*[=:]\s*\S+"),
    re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"),
)


@dataclass(frozen=True)
class Capture:
    command: str
    stdout: str

    @property
    def stdout_sha256(self) -> str:
        return sha256_bytes(self.stdout.encode())


@dataclass(frozen=True)
class TestTotals:
    passed: int
    failed: int
    ignored: int
    measured: int
    filtered: int


class ExecutionRow(TypedDict):
    deliveries: int
    certainty: str
    frontier: int | None
    keys: int


class IneligibilityRow(TypedDict):
    pristine_inexact: bool
    faulted_inexact: bool
    frontier_mismatch: bool


class VerdictRow(TypedDict):
    fixture: str
    schedule: str
    verdict: str
    pristine: ExecutionRow
    faulted: ExecutionRow
    ineligibility: IneligibilityRow


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when committed evidence differs from a fresh local capture",
    )
    arguments = parser.parse_args()

    captures = capture_evidence()
    outputs = build_outputs(captures)
    validate_outputs(outputs)

    if arguments.check:
        return check_outputs(outputs)
    write_outputs(outputs)
    return 0


def capture_evidence() -> dict[str, Capture]:
    return {
        "rustc": run(("rustc", "--version")),
        "cargo": run(("cargo", "--version")),
        "format": run(("cargo", "fmt", "--all", "--check")),
        "clippy": run(
            (
                "cargo",
                "clippy",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "-D",
                "warnings",
            )
        ),
        "tests": run(
            (
                "cargo",
                "test",
                "--all-targets",
                "--all-features",
                "--locked",
                "--",
                "--test-threads=1",
            )
        ),
        "release": run(
            (
                "cargo",
                "build",
                "--release",
                "--target",
                "x86_64-unknown-linux-musl",
                "--locked",
            )
        ),
        "linkage": run(
            (
                "readelf",
                "--program-headers",
                "--wide",
                "target/x86_64-unknown-linux-musl/release/kvcrucible",
            )
        ),
        "contract": run(
            ("cargo", "run", "--quiet", "--", "contract", "--format", "json")
        ),
        "fold": run(("cargo", "run", "--quiet", "--example", "delivered_fold")),
        "fault": run(("cargo", "run", "--quiet", "--example", "fault_materialization")),
        "verdicts": run(("cargo", "run", "--quiet", "--example", "verdict_matrix")),
    }


def run(command: tuple[str, ...]) -> Capture:
    environment = os.environ.copy()
    environment.update(
        {
            "CARGO_TERM_COLOR": "never",
            "NO_COLOR": "1",
            "RUST_BACKTRACE": "0",
        }
    )
    process = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    command_text = " ".join(command)
    if process.returncode != 0:
        raise RuntimeError(
            f"{command_text!r} failed with exit code {process.returncode}\n"
            f"stdout:\n{process.stdout}\n"
            f"stderr:\n{process.stderr}"
        )
    stdout = process.stdout.replace("\r\n", "\n")
    return Capture(command=command_text, stdout=stdout)


def build_outputs(captures: dict[str, Capture]) -> dict[str, bytes]:
    contract = json.loads(captures["contract"].stdout)
    raw_verdicts = json.loads(captures["verdicts"].stdout)
    validate_contract(contract)
    validate_verdicts(raw_verdicts)
    verdicts = cast(list[VerdictRow], raw_verdicts)
    tests = parse_test_totals(captures["tests"].stdout)
    validate_static_linkage(captures["linkage"].stdout)

    evidence = {
        "schema": "kvcrucible.visual-evidence/v1",
        "provenance": {
            "fixture_kind": "synthetic",
            "fixture_scope": (
                "offline bounded traces; no production engine or GPU is exercised"
            ),
            "rustc": captures["rustc"].stdout.strip(),
            "cargo": captures["cargo"].stdout.strip(),
            "trace_format": contract["trace_format"],
        },
        "quality_gate": {
            "format": "pass",
            "clippy": "pass",
            "static_musl_release": "pass",
            "dynamic_interpreter": "absent",
            "tests": {
                "passed": tests.passed,
                "failed": tests.failed,
                "ignored": tests.ignored,
                "measured": tests.measured,
                "filtered": tests.filtered,
            },
        },
        "contract": contract,
        "verdicts": verdicts,
        "captures": capture_metadata(captures, tests),
    }

    transcript = build_transcript(captures, tests)
    summary = build_summary(captures, contract, verdicts, tests)
    outputs: dict[str, bytes] = {
        "visual-evidence.json": encode_json(evidence),
        "terminal-transcript.txt": transcript.encode(),
        "evidence-summary.txt": summary.encode(),
        "terminal-evidence.svg": terminal_svg(captures, tests).encode(),
        "fault-timeline.svg": fault_timeline_svg(captures["fault"].stdout).encode(),
        "verdict-matrix.svg": verdict_matrix_svg(verdicts).encode(),
        "architecture.svg": architecture_svg().encode(),
        "certainty-decision.svg": certainty_decision_svg().encode(),
        "setup-workflow.svg": setup_workflow_svg(captures, tests).encode(),
    }
    outputs["manifest.sha256.json"] = build_manifest(outputs)
    return outputs


def capture_metadata(
    captures: dict[str, Capture],
    tests: TestTotals,
) -> dict[str, dict[str, object]]:
    metadata: dict[str, dict[str, object]] = {}
    for name, capture in captures.items():
        record: dict[str, object] = {"command": capture.command}
        if name == "tests":
            normalized = (
                f"passed={tests.passed};failed={tests.failed};"
                f"ignored={tests.ignored};measured={tests.measured};"
                f"filtered={tests.filtered}"
            )
            record["normalized_result"] = normalized
            record["normalized_result_sha256"] = sha256_bytes(normalized.encode())
        elif name in {"format", "clippy", "release", "linkage"}:
            record["result"] = "pass"
        else:
            record["stdout_sha256"] = capture.stdout_sha256
        metadata[name] = record
    return metadata


def validate_contract(contract: object) -> None:
    if not isinstance(contract, dict):
        raise TypeError("contract output must be a JSON object")
    required = {
        "project",
        "status",
        "trace_format",
        "implemented_capabilities",
        "planned_v0_1_capabilities",
        "non_goals",
    }
    if set(contract) != required:
        raise ValueError("contract output has an unexpected field set")
    if contract["project"] != "KVCrucible":
        raise ValueError("contract output belongs to an unexpected project")


def validate_verdicts(verdicts: object) -> None:
    if not isinstance(verdicts, list) or len(verdicts) != 3:
        raise ValueError("verdict evidence must contain exactly three scenarios")
    expected = (
        (
            "synthetic/reorder-and-duplicate",
            "Converged",
            ("Exact", 2, 3, 3),
            ("Exact", 2, 3, 4),
            (False, False, False),
        ),
        (
            "synthetic/same-cursor-selection",
            "Diverged",
            ("Exact", 0, 1, 2),
            ("Exact", 0, 1, 1),
            (False, False, False),
        ),
        (
            "synthetic/missing-middle-envelope",
            "Ineligible",
            ("Exact", 2, 3, 3),
            ("Unknown", 0, 1, 2),
            (False, True, True),
        ),
    )
    for row, facts in zip(verdicts, expected, strict=True):
        fixture, verdict, pristine, faulted, reasons = facts
        if not isinstance(row, dict):
            raise TypeError("each verdict row must be a JSON object")
        if row.get("fixture") != fixture or row.get("verdict") != verdict:
            raise ValueError(f"unexpected verdict identity for {fixture}")
        assert_execution(row.get("pristine"), pristine, fixture, "pristine")
        assert_execution(row.get("faulted"), faulted, fixture, "faulted")
        ineligibility = row.get("ineligibility")
        if not isinstance(ineligibility, dict):
            raise TypeError(f"{fixture} ineligibility evidence must be an object")
        actual_reasons = (
            ineligibility.get("pristine_inexact"),
            ineligibility.get("faulted_inexact"),
            ineligibility.get("frontier_mismatch"),
        )
        if actual_reasons != reasons:
            raise ValueError(f"unexpected ineligibility reasons for {fixture}")


def assert_execution(
    value: object,
    expected: tuple[str, int, int, int],
    fixture: str,
    side: str,
) -> None:
    if not isinstance(value, dict):
        raise TypeError(f"{fixture} {side} evidence must be an object")
    actual = (
        value.get("certainty"),
        value.get("frontier"),
        value.get("keys"),
        value.get("deliveries"),
    )
    if actual != expected:
        raise ValueError(f"unexpected {side} execution evidence for {fixture}")


def parse_test_totals(stdout: str) -> TestTotals:
    matches = list(TEST_RESULT.finditer(stdout))
    if not matches:
        raise ValueError("cargo test output did not contain a test result")
    totals = TestTotals(
        passed=sum(int(match["passed"]) for match in matches),
        failed=sum(int(match["failed"]) for match in matches),
        ignored=sum(int(match["ignored"]) for match in matches),
        measured=sum(int(match["measured"]) for match in matches),
        filtered=sum(int(match["filtered"]) for match in matches),
    )
    if totals.failed != 0 or totals.passed == 0:
        raise ValueError("quality-gate test totals are not a clean pass")
    return totals


def validate_static_linkage(stdout: str) -> None:
    if re.search(r"^\s*INTERP\s", stdout, re.MULTILINE):
        raise ValueError("release binary unexpectedly has a dynamic interpreter")


def build_transcript(
    captures: dict[str, Capture],
    tests: TestTotals,
) -> str:
    sections = [
        "KVCrucible verified local evidence",
        "fixture-kind: synthetic",
        ("scope: offline bounded traces; no production engine or GPU is exercised"),
        f"toolchain: {captures['rustc'].stdout.strip()}",
        "",
        f"$ {captures['contract'].command}",
        captures["contract"].stdout.rstrip(),
        "",
        f"$ {captures['fold'].command}",
        captures["fold"].stdout.rstrip(),
        "",
        f"$ {captures['fault'].command}",
        captures["fault"].stdout.rstrip(),
        "",
        f"$ {captures['verdicts'].command}",
        captures["verdicts"].stdout.rstrip(),
        "",
        f"$ {captures['format'].command}",
        "PASS",
        f"$ {captures['clippy'].command}",
        "PASS",
        f"$ {captures['tests'].command}",
        (
            f"PASS: {tests.passed} passed, {tests.failed} failed, "
            f"{tests.ignored} ignored"
        ),
        f"$ {captures['release'].command}",
        "PASS",
        f"$ {captures['linkage'].command}",
        "PASS: no INTERP program header",
        "",
    ]
    return "\n".join(sections)


def build_summary(
    captures: dict[str, Capture],
    contract: dict[str, object],
    verdicts: list[VerdictRow],
    tests: TestTotals,
) -> str:
    lines = [
        "KVCrucible evidence summary",
        "============================",
        f"Toolchain: {captures['rustc'].stdout.strip()}",
        f"Trace format: {contract['trace_format']}",
        "Fixture kind: synthetic, offline, CPU-only",
        (
            f"Quality gate: format pass; Clippy pass; "
            f"{counted(tests.passed, 'test')} pass; "
            f"{counted(tests.failed, 'failure')} observed"
        ),
        "Release target: x86_64-unknown-linux-musl build pass; no INTERP header",
        "",
        "Observed verdicts:",
    ]
    for row in verdicts:
        pristine = row["pristine"]
        faulted = row["faulted"]
        lines.append(
            f"- {row['fixture']}: {row['verdict']}; "
            f"pristine={pristine['certainty']}@{pristine['frontier']} "
            f"({counted(pristine['keys'], 'key')}/"
            f"{counted(pristine['deliveries'], 'delivery', 'deliveries')}); "
            f"faulted={faulted['certainty']}@{faulted['frontier']} "
            f"({counted(faulted['keys'], 'key')}/"
            f"{counted(faulted['deliveries'], 'delivery', 'deliveries')})"
        )
    lines.extend(
        (
            "",
            "Boundary:",
            (
                "- Evidence covers the implemented bounded trace, fault "
                "materialization, fold, and eligibility-aware oracle."
            ),
            (
                "- It does not claim replay orchestration, witness reduction, "
                "engine compatibility, serving correctness, or GPU inspection."
            ),
            "",
        )
    )
    return "\n".join(lines)


def counted(value: int, singular: str, plural: str | None = None) -> str:
    label = singular if value == 1 else (plural or f"{singular}s")
    return f"{value} {label}"


def terminal_svg(captures: dict[str, Capture], tests: TestTotals) -> str:
    fault_lines = captures["fault"].stdout.strip().splitlines()
    fold_lines = captures["fold"].stdout.strip().splitlines()
    lines: list[tuple[str, str]] = [
        (f"$ {captures['fault'].command}", CYAN),
        *((line, TEXT) for line in fault_lines),
        ("", TEXT),
        (f"$ {captures['fold'].command}", CYAN),
        *((line, TEXT) for line in fold_lines),
        ("", TEXT),
        (f"$ {captures['format'].command}", CYAN),
        ("PASS", GREEN),
        (f"$ {captures['clippy'].command}", CYAN),
        ("PASS", GREEN),
        (f"$ {captures['tests'].command}", CYAN),
        (f"PASS · {tests.passed} tests · {tests.failed} failed", GREEN),
    ]
    body = [
        rect(0, 0, 1440, 820, BACKGROUND),
        text(60, 66, "KVCrucible · verified terminal evidence", 30, TEXT, 700),
        text(
            60,
            101,
            "Fresh stdout from executable examples · synthetic fixtures · CPU-only",
            16,
            MUTED,
        ),
        pill(1120, 48, 122, "EXACT", GREEN),
        pill(1254, 48, 126, "OFFLINE", CYAN),
        rect(48, 132, 1344, 630, PANEL, radius=18, stroke=LINE),
        circle(80, 164, 7, RED),
        circle(104, 164, 7, AMBER),
        circle(128, 164, 7, GREEN),
        text(164, 171, "evidence capture", 14, MUTED, family="mono"),
    ]
    y = 207
    for value, color in lines:
        body.append(text(78, y, value, 15, color, family="mono"))
        y += 27
    body.extend(
        (
            text(
                60,
                796,
                "Transcript and SHA-256 bindings: docs/visuals/generated/",
                13,
                MUTED,
            ),
        )
    )
    return svg_document(
        "KVCrucible verified terminal evidence",
        (
            "Exact output from the fault materialization and delivered fold "
            "examples, followed by the local quality gates."
        ),
        1440,
        820,
        body,
    )


def fault_timeline_svg(stdout: str) -> str:
    observed = stdout.strip().splitlines()
    expected = [
        "e2#0 Buffered",
        "e0#0 Applied",
        "e1#0 Applied",
        "e1#1 Duplicate",
        "certainty=Exact frontier=Some(2) keys=3",
        "verdict=Converged pristine_deliveries=3 faulted_deliveries=4",
    ]
    if observed != expected:
        raise ValueError("fault materialization stdout changed unexpectedly")

    body = [
        rect(0, 0, 1440, 780, BACKGROUND),
        text(60, 66, "Deterministic fault execution", 30, TEXT, 700),
        text(
            60,
            101,
            "The diagram is derived from the freshly executed fault_materialization example",
            16,
            MUTED,
        ),
        pill(1224, 48, 156, "CONVERGED", GREEN),
        text(62, 166, "PRISTINE", 14, MUTED, 700),
        text(170, 166, "physical occurrence-zero order", 14, MUTED),
        rect(50, 188, 1340, 178, PANEL, radius=18, stroke=LINE),
        text(84, 222, "3 deliveries", 13, CYAN, 700),
        text(84, 343, "Exact · frontier 2 · 3 keys", 14, TEXT, 600),
        text(62, 420, "FAULTED", 14, MUTED, 700),
        text(170, 420, "duplicate e1, then move e2 before e0", 14, MUTED),
        rect(50, 442, 1340, 224, PANEL_ALT, radius=18, stroke=LINE),
        text(84, 476, "4 deliveries", 13, PURPLE, 700),
        text(84, 641, "Exact · frontier 2 · 3 keys", 14, TEXT, 600),
        rect(50, 700, 1340, 48, "#0b2a26", radius=14, stroke="#1f6f5f"),
        text(
            720,
            731,
            "same eligible cache view  →  Converged",
            16,
            GREEN,
            700,
            anchor="middle",
        ),
    ]

    pristine = (("e0#0", "Applied"), ("e1#0", "Applied"), ("e2#0", "Applied"))
    faulted = (
        ("e2#0", "Buffered"),
        ("e0#0", "Applied"),
        ("e1#0", "Applied"),
        ("e1#1", "Duplicate"),
    )
    body.extend(timeline_nodes(pristine, 300, 267, 360, CYAN))
    body.extend(timeline_nodes(faulted, 260, 535, 300, PURPLE))
    return svg_document(
        "KVCrucible deterministic fault execution",
        (
            "Pristine and faulted delivery timelines show the observed "
            "dispositions and equal exact final state."
        ),
        1440,
        780,
        body,
    )


def verdict_matrix_svg(verdicts: list[VerdictRow]) -> str:
    colors = {"Converged": GREEN, "Diverged": RED, "Ineligible": AMBER}
    titles = {
        "Converged": "Equivalent exact views",
        "Diverged": "Different exact views",
        "Ineligible": "Evidence cannot decide",
    }
    body = [
        rect(0, 0, 1440, 850, BACKGROUND),
        text(60, 66, "Eligibility-aware verdict matrix", 30, TEXT, 700),
        text(
            60,
            101,
            "Three executed synthetic traces · one real outcome from each oracle branch",
            16,
            MUTED,
        ),
        pill(1220, 48, 160, "EXECUTED", CYAN),
    ]
    for index, row in enumerate(verdicts):
        x = 50 + index * 460
        verdict = str(row["verdict"])
        color = colors[verdict]
        pristine = row["pristine"]
        faulted = row["faulted"]
        reasons = row["ineligibility"]
        body.extend(
            (
                rect(x, 145, 420, 620, PANEL, radius=20, stroke=LINE),
                rect(x, 145, 420, 8, color, radius=4),
                text(x + 28, 196, verdict, 24, color, 800),
                text(x + 28, 229, titles[verdict], 15, TEXT, 600),
                text(x + 28, 270, "FIXTURE", 12, MUTED, 700),
                text(
                    x + 28,
                    297,
                    str(row["fixture"]).removeprefix("synthetic/"),
                    14,
                    TEXT,
                    family="mono",
                ),
                text(x + 28, 340, "PRISTINE", 12, CYAN, 700),
                metric_panel(x + 28, 356, pristine, CYAN),
                text(x + 28, 490, "FAULTED", 12, PURPLE, 700),
                metric_panel(x + 28, 506, faulted, PURPLE),
                text(x + 28, 640, "ELIGIBILITY", 12, MUTED, 700),
                text(
                    x + 28,
                    671,
                    eligibility_text(reasons),
                    14,
                    color,
                    600,
                ),
                text(
                    x + 28,
                    711,
                    f"schedule · {row['schedule']}",
                    12,
                    MUTED,
                    family="mono",
                ),
            )
        )
    body.extend(
        (
            text(
                60,
                815,
                (
                    "Source: cargo run --quiet --example verdict_matrix · "
                    "full facts are preserved in visual-evidence.json"
                ),
                13,
                MUTED,
            ),
        )
    )
    return svg_document(
        "KVCrucible eligibility-aware verdict matrix",
        (
            "Executed Converged, Diverged, and Ineligible scenarios with "
            "pristine and faulted evidence facts."
        ),
        1440,
        850,
        body,
    )


def architecture_svg() -> str:
    body = [
        rect(0, 0, 1440, 1180, BACKGROUND),
        text(60, 66, "Implemented evidence architecture", 30, TEXT, 700),
        text(
            60,
            101,
            "One owned trace · bounded work · executable capability only after EOF",
            16,
            MUTED,
        ),
        pill(1182, 48, 198, "CURRENT BOUNDARY", GREEN),
        rect(50, 165, 290, 120, PANEL, radius=18, stroke=CYAN),
        text(78, 204, "UNTRUSTED INPUT", 12, CYAN, 800),
        text(78, 238, "bounded JSONL decode", 17, TEXT, 700),
        text(78, 264, "bytes → ValidatedRecord", 13, MUTED),
        *arrow(340, 225, 390, 225, CYAN),
        rect(390, 130, 1000, 365, PANEL, radius=22, stroke=LINE),
        text(425, 170, "TraceAssembler · sticky-failed owner", 18, TEXT, 700),
        text(
            425,
            196,
            "The same owned records enter both coordinated layers",
            13,
            MUTED,
        ),
        rect(425, 225, 420, 160, PANEL_ALT, radius=16, stroke=CYAN),
        text(453, 260, "STRUCTURAL VALIDATOR", 12, CYAN, 800),
        text(453, 294, "record order + identities", 16, TEXT, 700),
        text(453, 322, "schedule prefixes + numeric plan", 14, MUTED),
        text(453, 350, "bounded trace accounting", 14, MUTED),
        rect(935, 225, 420, 160, PANEL_ALT, radius=16, stroke=PURPLE),
        text(963, 260, "ENVELOPE NORMALIZER", 12, PURPLE, 800),
        text(963, 294, "semantic fingerprints", 16, TEXT, 700),
        text(963, 322, "stream blueprints + sources", 14, MUTED),
        text(963, 350, "session-wide work budget", 14, MUTED),
        line(635, 385, 635, 407, LINE, 3),
        line(1145, 385, 1145, 407, LINE, 3),
        line(635, 407, 890, 407, LINE, 3),
        line(1145, 407, 890, 407, LINE, 3),
        *arrow(890, 407, 890, 423, GREEN),
        rect(590, 423, 600, 54, "#0b2a26", radius=14, stroke=GREEN),
        text(
            890,
            457,
            "EOF success  →  SealedTrace capability",
            16,
            GREEN,
            800,
            anchor="middle",
        ),
        text(60, 545, "FRESH PAIRED EXECUTION", 12, MUTED, 800),
        rect(70, 570, 590, 205, PANEL, radius=20, stroke=CYAN),
        text(100, 610, "PRISTINE", 13, CYAN, 800),
        text(100, 646, "physical occurrence-zero order", 17, TEXT, 700),
        text(100, 679, "fresh per-stream fold states", 14, MUTED),
        text(100, 708, "exact · recovering · unknown", 14, MUTED),
        text(100, 741, "no fault action inferred", 13, CYAN, 600),
        rect(780, 570, 590, 205, PANEL, radius=20, stroke=PURPLE),
        text(810, 610, "FAULTED", 13, PURPLE, 800),
        text(810, 646, "indexed schedule materializer", 17, TEXT, 700),
        text(810, 679, "drop · duplicate · reorder", 14, MUTED),
        text(810, 708, "shared immutable prepared sources", 14, MUTED),
        text(810, 741, "fresh per-stream fold states", 13, PURPLE, 600),
        line(890, 477, 890, 530, LINE, 3),
        line(365, 530, 1075, 530, LINE, 3),
        *arrow(365, 530, 365, 570, CYAN),
        *arrow(1075, 530, 1075, 570, PURPLE),
        *arrow(365, 775, 600, 835, CYAN),
        *arrow(1075, 775, 840, 835, PURPLE),
        rect(390, 835, 660, 100, PANEL_ALT, radius=18, stroke=GREEN),
        text(720, 872, "ELIGIBILITY GATE", 12, GREEN, 800, anchor="middle"),
        text(
            720,
            904,
            "both exact + authoritative · same frontier",
            16,
            TEXT,
            700,
            anchor="middle",
        ),
        line(720, 935, 720, 965, GREEN, 3),
        line(360, 965, 1080, 965, LINE, 3),
        *arrow(360, 965, 360, 980, GREEN),
        *arrow(720, 965, 720, 980, RED),
        *arrow(1080, 965, 1080, 980, AMBER),
        rect(220, 980, 280, 72, "#0b2a26", radius=16, stroke=GREEN),
        text(360, 1015, "Converged", 18, GREEN, 800, anchor="middle"),
        text(360, 1038, "equal view", 12, MUTED, anchor="middle"),
        rect(580, 980, 280, 72, "#311523", radius=16, stroke=RED),
        text(720, 1015, "Diverged", 18, RED, 800, anchor="middle"),
        text(720, 1038, "different view", 12, MUTED, anchor="middle"),
        rect(940, 980, 280, 72, "#302611", radius=16, stroke=AMBER),
        text(1080, 1015, "Ineligible", 18, AMBER, 800, anchor="middle"),
        text(1080, 1038, "insufficient evidence", 12, MUTED, anchor="middle"),
        dashed_line(50, 1090, 1390, 1090, LINE, 2),
        text(60, 1120, "PLANNED · OUTSIDE THIS EVIDENCE", 12, MUTED, 800),
        pill(380, 1102, 180, "REPLAY EVENTS", MUTED),
        pill(580, 1102, 178, "1-MINIMAL WITNESS", MUTED),
        pill(778, 1102, 168, "vLLM ADAPTER", MUTED),
        pill(966, 1102, 180, "REPORT CLI", MUTED),
    ]
    return svg_document(
        "KVCrucible implemented evidence architecture",
        (
            "Bounded JSONL validation and normalization seal one executable "
            "trace, then fresh pristine and faulted folds feed an "
            "eligibility-aware convergence oracle. Planned layers are separate."
        ),
        1440,
        1180,
        body,
    )


def certainty_decision_svg() -> str:
    body = [
        rect(0, 0, 1440, 920, BACKGROUND),
        text(60, 66, "How KVCrucible reaches a verdict", 30, TEXT, 700),
        text(
            60,
            101,
            "Unknown evidence is not silently converted into a cache divergence",
            16,
            MUTED,
        ),
        pill(1216, 48, 164, "FAIL CLOSED", AMBER),
        rect(430, 145, 580, 82, PANEL, radius=18, stroke=LINE),
        text(
            720,
            179,
            "pristine summary + faulted summary",
            17,
            TEXT,
            700,
            anchor="middle",
        ),
        text(
            720,
            205,
            "same visible publisher stream",
            13,
            MUTED,
            anchor="middle",
        ),
        *arrow(720, 227, 720, 265, LINE),
        rect(420, 265, 600, 94, PANEL_ALT, radius=18, stroke=CYAN),
        text(
            720,
            305,
            "Are both summaries exact + authoritative?",
            17,
            TEXT,
            700,
            anchor="middle",
        ),
        text(
            720,
            334,
            "no active unknown reason or pending evidence",
            13,
            MUTED,
            anchor="middle",
        ),
        text(1038, 316, "NO", 12, AMBER, 800),
        *arrow(1020, 312, 1135, 312, AMBER),
        rect(1135, 270, 255, 92, "#302611", radius=16, stroke=AMBER),
        text(1262, 308, "Ineligible", 18, AMBER, 800, anchor="middle"),
        text(1262, 336, "inexact side flagged", 12, MUTED, anchor="middle"),
        text(735, 383, "YES", 12, GREEN, 800),
        *arrow(720, 359, 720, 415, GREEN),
        rect(420, 415, 600, 82, PANEL_ALT, radius=18, stroke=PURPLE),
        text(
            720,
            465,
            "Did both sides reach the same frontier?",
            17,
            TEXT,
            700,
            anchor="middle",
        ),
        text(1038, 456, "NO", 12, AMBER, 800),
        *arrow(1020, 456, 1135, 456, AMBER),
        rect(1135, 414, 255, 92, "#302611", radius=16, stroke=AMBER),
        text(1262, 452, "Ineligible", 18, AMBER, 800, anchor="middle"),
        text(1262, 480, "frontier mismatch", 12, MUTED, anchor="middle"),
        text(735, 521, "YES", 12, GREEN, 800),
        *arrow(720, 497, 720, 555, GREEN),
        rect(420, 555, 600, 82, PANEL_ALT, radius=18, stroke=GREEN),
        text(
            720,
            605,
            "Are canonical scope + cache membership equal?",
            17,
            TEXT,
            700,
            anchor="middle",
        ),
        text(512, 665, "YES", 12, GREEN, 800),
        text(914, 665, "NO", 12, RED, 800),
        *arrow(620, 637, 360, 700, GREEN),
        *arrow(820, 637, 1080, 700, RED),
        rect(190, 700, 340, 94, "#0b2a26", radius=18, stroke=GREEN),
        text(360, 742, "Converged", 21, GREEN, 800, anchor="middle"),
        text(360, 770, "eligible and equal", 13, MUTED, anchor="middle"),
        rect(910, 700, 340, 94, "#311523", radius=18, stroke=RED),
        text(1080, 742, "Diverged", 21, RED, 800, anchor="middle"),
        text(1080, 770, "eligible but different", 13, MUTED, anchor="middle"),
        rect(50, 820, 1340, 70, PANEL, radius=14, stroke=LINE),
        text(
            720,
            847,
            "Every active inexact/frontier flag is retained in the result",
            13,
            MUTED,
            600,
            anchor="middle",
        ),
        text(
            720,
            874,
            "Hard fold/resource errors remain typed errors · they are never verdicts",
            13,
            MUTED,
            600,
            anchor="middle",
        ),
    ]
    return svg_document(
        "KVCrucible convergence verdict decision tree",
        (
            "Exactness and frontier equality are eligibility preconditions. "
            "Only eligible cache views can converge or diverge; otherwise the "
            "result is ineligible."
        ),
        1440,
        920,
        body,
    )


def setup_workflow_svg(
    captures: dict[str, Capture],
    tests: TestTotals,
) -> str:
    toolchain = captures["rustc"].stdout.strip().split()[1]
    body = [
        rect(0, 0, 1440, 910, BACKGROUND),
        text(60, 66, "Local reproduction workflow", 30, TEXT, 700),
        text(
            60,
            101,
            "Evidence run: CPU-only · no model download · no runtime service",
            16,
            MUTED,
        ),
        pill(1198, 48, 182, "LOCAL EVIDENCE", CYAN),
        step_card(
            50,
            150,
            650,
            220,
            "01",
            "Inspect the current boundary",
            (
                "$ cargo run -- contract",
                "$ cargo run -- contract --format json",
            ),
            CYAN,
        ),
        step_card(
            740,
            150,
            650,
            220,
            "02",
            "Execute the delivered fold",
            ("$ cargo run --example delivered_fold",),
            PURPLE,
        ),
        step_card(
            50,
            410,
            650,
            220,
            "03",
            "Materialize and compare faults",
            (
                "$ cargo run --example fault_materialization",
                "$ cargo run --example verdict_matrix",
            ),
            GREEN,
        ),
        step_card(
            740,
            410,
            650,
            220,
            "04",
            "Regenerate and verify evidence",
            (
                "$ python3 tools/render_readme_visuals.py",
                "$ python3 tools/render_readme_visuals.py --check",
            ),
            AMBER,
        ),
        text(60, 686, "FRESHLY EXECUTED GATES", 12, MUTED, 800),
        quality_card(50, 710, 310, "TOOLCHAIN", f"Rust {toolchain}", CYAN),
        quality_card(390, 710, 310, "STATIC ANALYSIS", "fmt + Clippy pass", PURPLE),
        quality_card(
            730,
            710,
            310,
            "TEST CORPUS",
            f"{counted(tests.passed, 'test')} · {counted(tests.failed, 'failure')}",
            GREEN,
        ),
        quality_card(
            1070,
            710,
            320,
            "RELEASE TARGET",
            "static musl · no INTERP",
            AMBER,
        ),
        text(
            60,
            872,
            (
                "Every generated asset is deterministic, privacy-checked, and "
                "bound to source/output SHA-256 digests."
            ),
            13,
            MUTED,
        ),
    ]
    return svg_document(
        "KVCrucible local reproduction workflow",
        (
            "Four local steps inspect the contract, execute folds and fault "
            "scenarios, then regenerate checked visual evidence. Fresh quality "
            "gates show the pinned toolchain, tests, and static release target."
        ),
        1440,
        910,
        body,
    )


def step_card(
    x: int,
    y: int,
    width: int,
    height: int,
    number: str,
    heading: str,
    commands: tuple[str, ...],
    accent: str,
) -> str:
    fragments = [
        rect(x, y, width, height, PANEL, radius=20, stroke=LINE),
        circle(x + 48, y + 47, 25, accent),
        text(
            x + 48,
            y + 53,
            number,
            12,
            BACKGROUND,
            900,
            anchor="middle",
        ),
        text(x + 88, y + 54, heading, 18, TEXT, 700),
        rect(x + 30, y + 88, width - 60, 102, PANEL_ALT, radius=12),
    ]
    command_y = y + 125
    for command in commands:
        fragments.append(text(x + 50, command_y, command, 14, accent, family="mono"))
        command_y += 36
    return "".join(fragments)


def quality_card(
    x: int,
    y: int,
    width: int,
    label: str,
    value: str,
    accent: str,
) -> str:
    return "".join(
        (
            rect(x, y, width, 112, PANEL, radius=16, stroke=LINE),
            text(x + 22, y + 34, label, 11, MUTED, 800),
            text(x + 22, y + 75, value, 16, accent, 700),
        )
    )


def metric_panel(
    x: int,
    y: int,
    execution: ExecutionRow,
    accent: str,
) -> str:
    return "".join(
        (
            rect(x, y, 364, 108, PANEL_ALT, radius=12, stroke=LINE),
            text(x + 18, y + 31, str(execution["certainty"]), 17, accent, 700),
            text(
                x + 18,
                y + 61,
                (
                    f"frontier {execution['frontier']}  ·  "
                    f"{counted(execution['keys'], 'key')}"
                ),
                14,
                TEXT,
                600,
            ),
            text(
                x + 18,
                y + 88,
                (
                    f"{counted(execution['deliveries'], 'admitted delivery', 'admitted deliveries')}"
                ),
                13,
                MUTED,
            ),
        )
    )


def eligibility_text(reasons: IneligibilityRow) -> str:
    active = []
    if reasons["pristine_inexact"]:
        active.append("pristine inexact")
    if reasons["faulted_inexact"]:
        active.append("faulted inexact")
    if reasons["frontier_mismatch"]:
        active.append("frontier mismatch")
    return "eligible comparison" if not active else " · ".join(active)


def timeline_nodes(
    nodes: Iterable[tuple[str, str]],
    start_x: int,
    y: int,
    gap: int,
    accent: str,
) -> list[str]:
    values = list(nodes)
    fragments: list[str] = []
    for index, (identity, disposition) in enumerate(values):
        x = start_x + index * gap
        if index:
            fragments.extend(
                (
                    line(x - gap + 132, y + 41, x - 18, y + 41, LINE, 3),
                    polygon(
                        (
                            (x - 18, y + 41),
                            (x - 31, y + 34),
                            (x - 31, y + 48),
                        ),
                        LINE,
                    ),
                )
            )
        fragments.extend(
            (
                rect(x, y, 132, 82, PANEL_ALT, radius=12, stroke=accent),
                text(x + 66, y + 33, identity, 16, TEXT, 700, anchor="middle"),
                text(
                    x + 66,
                    y + 61,
                    disposition,
                    12,
                    accent,
                    700,
                    anchor="middle",
                ),
            )
        )
    return fragments


def build_manifest(outputs: dict[str, bytes]) -> bytes:
    manifest = {
        "schema": "kvcrucible.visual-manifest/v1",
        "inputs": [
            {"path": path, "sha256": sha256_file(ROOT / path)}
            for path in manifest_source_paths()
        ],
        "outputs": [
            {"path": f"docs/visuals/generated/{name}", "sha256": sha256_bytes(body)}
            for name, body in sorted(outputs.items())
        ],
    }
    return encode_json(manifest)


def manifest_source_paths() -> tuple[str, ...]:
    paths = set(SOURCE_PATHS)
    for pattern in SOURCE_GLOBS:
        paths.update(
            path.relative_to(ROOT).as_posix()
            for path in ROOT.glob(pattern)
            if path.is_file()
        )
    return tuple(sorted(paths))


def validate_outputs(outputs: dict[str, bytes]) -> None:
    if set(outputs) != set(EXPECTED_OUTPUTS):
        raise ValueError("generator produced an unexpected output set")
    forbidden_values = {
        str(ROOT),
        str(Path.home()),
        socket.gethostname(),
        os.environ.get("USER", ""),
        os.environ.get("LOGNAME", ""),
    }
    forbidden_values.discard("")
    for name, body in outputs.items():
        decoded = body.decode("utf-8")
        if "\x1b" in decoded:
            raise ValueError(f"{name} contains a terminal escape sequence")
        for value in forbidden_values:
            if value and value in decoded:
                raise ValueError(f"{name} contains host-specific data")
        for pattern in SENSITIVE_PATTERNS:
            if pattern.search(decoded):
                raise ValueError(f"{name} contains sensitive-looking data")


def check_outputs(outputs: dict[str, bytes]) -> int:
    if not OUTPUT_DIRECTORY.is_dir():
        print("visual evidence directory is missing", file=sys.stderr)
        return 1
    existing = {path.name for path in OUTPUT_DIRECTORY.iterdir() if path.is_file()}
    expected = set(EXPECTED_OUTPUTS)
    if existing != expected:
        missing = sorted(expected - existing)
        unexpected = sorted(existing - expected)
        if missing:
            print(f"missing generated files: {', '.join(missing)}", file=sys.stderr)
        if unexpected:
            print(
                f"unexpected generated files: {', '.join(unexpected)}",
                file=sys.stderr,
            )
        return 1
    stale = [
        name
        for name, expected_body in outputs.items()
        if (OUTPUT_DIRECTORY / name).read_bytes() != expected_body
    ]
    if stale:
        print(f"stale generated files: {', '.join(sorted(stale))}", file=sys.stderr)
        return 1
    print("KVCrucible visual evidence is current")
    return 0


def write_outputs(outputs: dict[str, bytes]) -> None:
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    existing = {path.name for path in OUTPUT_DIRECTORY.iterdir() if path.is_file()}
    unexpected = existing - set(EXPECTED_OUTPUTS)
    if unexpected:
        raise ValueError(
            "refusing to overwrite a directory with unexpected files: "
            + ", ".join(sorted(unexpected))
        )
    for name, body in outputs.items():
        (OUTPUT_DIRECTORY / name).write_bytes(body)
    print(f"wrote {len(outputs)} files to docs/visuals/generated")


def encode_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def svg_document(
    title_value: str,
    description: str,
    width: int,
    height: int,
    body: Iterable[str],
) -> str:
    title_id = "title"
    description_id = "description"
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}" role="img" '
        f'aria-labelledby="{title_id} {description_id}">\n'
        f'  <title id="{title_id}">{escape(title_value)}</title>\n'
        f'  <desc id="{description_id}">{escape(description)}</desc>\n'
        f"  <g>{''.join(body)}</g>\n"
        "</svg>\n"
    )


def rect(
    x: int,
    y: int,
    width: int,
    height: int,
    fill: str,
    *,
    radius: int = 0,
    stroke: str | None = None,
) -> str:
    stroke_attribute = "" if stroke is None else f' stroke="{stroke}"'
    return (
        f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
        f'rx="{radius}" fill="{fill}"{stroke_attribute}/>'
    )


def circle(x: int, y: int, radius: int, fill: str) -> str:
    return f'<circle cx="{x}" cy="{y}" r="{radius}" fill="{fill}"/>'


def line(
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    stroke: str,
    width: int,
) -> str:
    return (
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
        f'stroke="{stroke}" stroke-width="{width}"/>'
    )


def dashed_line(
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    stroke: str,
    width: int,
) -> str:
    return (
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" '
        f'stroke="{stroke}" stroke-width="{width}" stroke-dasharray="8 8"/>'
    )


def arrow(
    x1: int,
    y1: int,
    x2: int,
    y2: int,
    stroke: str,
    width: int = 3,
) -> list[str]:
    fragments = [line(x1, y1, x2, y2, stroke, width)]
    delta_x = x2 - x1
    delta_y = y2 - y1
    if abs(delta_x) >= abs(delta_y):
        direction = 1 if delta_x >= 0 else -1
        points = (
            (x2, y2),
            (x2 - 13 * direction, y2 - 7),
            (x2 - 13 * direction, y2 + 7),
        )
    else:
        direction = 1 if delta_y >= 0 else -1
        points = (
            (x2, y2),
            (x2 - 7, y2 - 13 * direction),
            (x2 + 7, y2 - 13 * direction),
        )
    fragments.append(polygon(points, stroke))
    return fragments


def polygon(points: Iterable[tuple[int, int]], fill: str) -> str:
    encoded = " ".join(f"{x},{y}" for x, y in points)
    return f'<polygon points="{encoded}" fill="{fill}"/>'


def text(
    x: int,
    y: int,
    value: str,
    size: int,
    fill: str,
    weight: int = 400,
    *,
    family: str = "sans",
    anchor: str = "start",
) -> str:
    font = (
        "DejaVu Sans Mono, ui-monospace, monospace"
        if family == "mono"
        else "DejaVu Sans, Arial, sans-serif"
    )
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-family="{font}" '
        f'font-size="{size}" font-weight="{weight}" '
        f'text-anchor="{anchor}">{escape(value)}</text>'
    )


def pill(x: int, y: int, width: int, value: str, color: str) -> str:
    return "".join(
        (
            rect(x, y, width, 34, PANEL_ALT, radius=17, stroke=color),
            text(
                x + width // 2,
                y + 23,
                value,
                12,
                color,
                800,
                anchor="middle",
            ),
        )
    )


def escape(value: object) -> str:
    return html.escape(str(value), quote=True)


if __name__ == "__main__":
    raise SystemExit(main())
