from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, TypeAlias, cast

WIDTH: Final = 1440
HEIGHT: Final = 820
PNG_NAME: Final = "terminal-transcript.png"
GIF_NAME: Final = "verdict-fault-workflow.gif"
MANIFEST_NAME: Final = "manifest.sha256.json"
EXPECTED_OUTPUTS: Final = (MANIFEST_NAME, PNG_NAME, GIF_NAME)
MANIFEST_SCHEMA: Final = "kvcrucible.readme-media-manifest/v1"
EVIDENCE_SCHEMA: Final = "kvcrucible.visual-evidence/v2"
DISCLAIMER: Final = (
    "EVIDENCE-DERIVED | SYNTHETIC OFFLINE FIXTURE | "
    "NOT OS CAPTURE | NOT BENCHMARK"
)
FRAME_COMMENT_PREFIX: Final = b"KVCRUCIBLE-FRAME-V1\x00"
MAX_SOURCE_BYTES: Final = 512 * 1024
MAX_OUTPUT_BYTES: Final = 2 * 1024 * 1024
MAX_TOTAL_OUTPUT_BYTES: Final = 4 * 1024 * 1024
LOWER_GIT_SHA: Final = re.compile(r"^[0-9a-f]{40}$")
LOWER_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")

TRANSCRIPT_PATH: Final = "docs/visuals/generated/terminal-transcript.txt"
EVIDENCE_PATH: Final = "docs/visuals/generated/visual-evidence.json"
GENERATOR_PATH: Final = "tools/render_readme_media.py"
AUDITOR_PATH: Final = "scripts/verify_readme_media.py"
EVIDENCE_PATHS: Final = tuple(sorted((EVIDENCE_PATH, TRANSCRIPT_PATH)))
TOOL_PATHS: Final = tuple(sorted((AUDITOR_PATH, GENERATOR_PATH)))
SOURCE_PATHS: Final = tuple(sorted((*EVIDENCE_PATHS, *TOOL_PATHS)))

CLAIM_BOUNDARY: Final[dict[str, str | bool]] = {
    "benchmark": False,
    "evidence_class": "executable-derived-synthetic-fixture",
    "gpu_exercised": False,
    "os_capture": False,
    "production_engine_exercised": False,
    "scope": "offline bounded traces",
}

PALETTE: Final[tuple[tuple[int, int, int], ...]] = (
    (7, 17, 31),
    (15, 27, 45),
    (17, 31, 52),
    (51, 65, 85),
    (230, 237, 247),
    (159, 176, 199),
    (94, 234, 212),
    (96, 165, 250),
    (167, 139, 250),
    (52, 211, 153),
    (251, 191, 36),
    (251, 113, 133),
    (30, 41, 59),
    (71, 85, 105),
    (203, 213, 225),
    (2, 6, 23),
)
BACKGROUND: Final = 0
PANEL: Final = 1
PANEL_ALT: Final = 2
LINE: Final = 3
TEXT: Final = 4
MUTED: Final = 5
CYAN: Final = 6
BLUE: Final = 7
PURPLE: Final = 8
GREEN: Final = 9
AMBER: Final = 10
RED: Final = 11

FRAME_STAGES: Final = (
    "fault-schedule",
    "fault-result",
    "converged",
    "diverged",
    "ineligible",
    "decision-boundary",
)
FRAME_DELAYS_CS: Final = (140, 160, 180, 200, 220, 300)

_FONT_SOURCE: Final = """
32 00000000000000
33 04040404040004
35 0a1f0a0a1f0a00
36 040f140e051e04
40 02040808080402
41 08040202020408
44 00000000000408
45 0000000e000000
46 00000000000004
47 01020408100000
48 0e11131519110e
49 040c040404040e
50 0e11010204081f
51 1e01010601111e
52 02060a121f0202
53 1f101e0101110e
54 0608101e11110e
55 1f010204080808
56 0e11110e11110e
57 0e11110f01020c
58 00040000040000
59 00040000040408
60 02040810080402
61 001f001f000000
62 08040201020408
63 0e110204040004
65 0e11111f111111
66 1e11111e11111e
67 0f10101010100f
68 1e11111111111e
69 1f10101e10101f
70 1f10101e101010
71 0f10101711110f
72 1111111f111111
73 0e04040404040e
74 0702020212120c
75 11121418141211
76 1010101010101f
77 111b1515111111
78 11191915131311
79 0e11111111110e
80 1e11111e101010
81 0e11111115120d
82 1e11111e141211
83 0f10100e01011e
84 1f040404040404
85 1111111111110e
86 11111111110a04
87 11111115151b11
88 11110a040a1111
89 11110a04040404
90 1f01020408101f
91 0e08080808080e
92 10080402010000
93 0e02020202020e
95 0000000000001f
97 00000e011f111f
98 10101e1111111e
99 00000f1010100f
100 01010f1111110f
101 00000e111f100f
102 0609081c080808
103 000f11110f011e
104 10101e11111111
105 04000c0404040e
106 0200060202120c
107 10101214181211
108 0c04040404040e
109 00001a15151515
110 00001e11111111
111 00000e1111110e
112 00001e111e1010
113 00000f110f0101
114 00001619101010
115 00000f100e011e
116 08081c08080906
117 0000111111110f
118 00001111110a04
119 0000111515150a
120 0000110a040a11
121 000011110f011e
122 00001f0204081f
124 04040404040404
183 00000004000000
"""


JSONScalar: TypeAlias = bool | int | str | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


class MediaError(RuntimeError):
    """Raised when deterministic README media cannot be trusted."""


def _font() -> dict[str, tuple[int, ...]]:
    result: dict[str, tuple[int, ...]] = {}
    for line in _FONT_SOURCE.strip().splitlines():
        raw_codepoint, encoded = line.split()
        if len(encoded) != 14:
            raise MediaError("embedded glyph has an invalid row count")
        rows = tuple(int(encoded[index : index + 2], 16) for index in range(0, 14, 2))
        if any(row > 0x1F for row in rows):
            raise MediaError("embedded glyph exceeds five columns")
        result[chr(int(raw_codepoint))] = rows
    return result


FONT: Final = _font()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: JSONValue) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise MediaError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json(data: bytes, *, label: str) -> dict[str, JSONValue]:
    if not data or len(data) > MAX_SOURCE_BYTES or not data.endswith(b"\n"):
        raise MediaError(f"{label} violates its canonical byte contract")
    try:
        value = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MediaError(f"{label} is not valid JSON") from error
    expected = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if not isinstance(value, dict) or expected != data:
        raise MediaError(f"{label} is not canonical pretty JSON")
    return cast(dict[str, JSONValue], value)


def _dict(value: JSONValue, *, label: str) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise MediaError(f"{label} must be an object")
    return value


def _list(value: JSONValue, *, label: str) -> list[JSONValue]:
    if not isinstance(value, list):
        raise MediaError(f"{label} must be an array")
    return value


def _str(value: JSONValue, *, label: str) -> str:
    if not isinstance(value, str):
        raise MediaError(f"{label} must be a string")
    return value


def _int(value: JSONValue, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise MediaError(f"{label} must be an integer")
    return value


def _bool(value: JSONValue, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise MediaError(f"{label} must be a boolean")
    return value


EXPECTED_VERDICTS: Final[list[JSONValue]] = [
    {
        "faulted": {
            "certainty": "Exact",
            "fingerprint_window": 4096,
            "frontier": 2,
            "keys": 3,
            "processed_deliveries": 4,
            "stale_unverifiable": 0,
        },
        "fixture": "synthetic/reorder-and-duplicate",
        "ineligibility": {
            "faulted_inexact": False,
            "frontier_mismatch": False,
            "pristine_inexact": False,
        },
        "pristine": {
            "certainty": "Exact",
            "fingerprint_window": 4096,
            "frontier": 2,
            "keys": 3,
            "processed_deliveries": 3,
            "stale_unverifiable": 0,
        },
        "schedule": "reorder-and-duplicate",
        "stream": "s",
        "verdict": "Converged",
    },
    {
        "faulted": {
            "certainty": "Exact",
            "fingerprint_window": 0,
            "frontier": 0,
            "keys": 1,
            "processed_deliveries": 1,
            "stale_unverifiable": 0,
        },
        "fixture": "synthetic/same-cursor-selection",
        "ineligibility": {
            "faulted_inexact": False,
            "frontier_mismatch": False,
            "pristine_inexact": False,
        },
        "pristine": {
            "certainty": "Exact",
            "fingerprint_window": 0,
            "frontier": 0,
            "keys": 1,
            "processed_deliveries": 2,
            "stale_unverifiable": 1,
        },
        "schedule": "select-second",
        "stream": "s",
        "verdict": "Diverged",
    },
    {
        "faulted": {
            "certainty": "Unknown",
            "fingerprint_window": 4096,
            "frontier": 0,
            "keys": 1,
            "processed_deliveries": 2,
            "stale_unverifiable": 0,
        },
        "fixture": "synthetic/missing-middle-envelope",
        "ineligibility": {
            "faulted_inexact": True,
            "frontier_mismatch": True,
            "pristine_inexact": False,
        },
        "pristine": {
            "certainty": "Exact",
            "fingerprint_window": 4096,
            "frontier": 2,
            "keys": 3,
            "processed_deliveries": 3,
            "stale_unverifiable": 0,
        },
        "schedule": "drop-middle",
        "stream": "s",
        "verdict": "Ineligible",
    },
]


def _section(lines: list[str], command: str) -> bytes:
    marker = f"$ {command}"
    matches = [index for index, line in enumerate(lines) if line == marker]
    if len(matches) != 1:
        raise MediaError(f"transcript command is not unique: {command}")
    start = matches[0] + 1
    end = start
    while end < len(lines) and lines[end]:
        end += 1
    if end == start:
        raise MediaError(f"transcript command has no stdout: {command}")
    return ("\n".join(lines[start:end]) + "\n").encode("utf-8")


def _capture(
    captures: dict[str, JSONValue],
    name: str,
    expected_command: str,
) -> dict[str, JSONValue]:
    record = _dict(captures.get(name), label=f"{name} capture")
    if record.get("command") != expected_command:
        raise MediaError(f"{name} capture command differs")
    return record


def _validate_sources(sources: Mapping[str, bytes]) -> dict[str, JSONValue]:
    if tuple(sorted(sources)) != SOURCE_PATHS:
        raise MediaError("source inventory is not closed")
    for path, body in sources.items():
        if not body or len(body) > MAX_SOURCE_BYTES:
            raise MediaError(f"source {path} exceeds its byte budget")

    evidence = _json(sources[EVIDENCE_PATH], label="visual evidence")
    if set(evidence) != {
        "captures",
        "contract",
        "provenance",
        "quality_gate",
        "schema",
        "verdicts",
    }:
        raise MediaError("visual evidence field set differs")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        raise MediaError("visual evidence schema differs")

    provenance = _dict(evidence.get("provenance"), label="provenance")
    if (
        provenance.get("fixture_kind") != "synthetic"
        or provenance.get("fixture_scope")
        != "offline bounded traces; no production engine or GPU is exercised"
        or provenance.get("trace_format") != "kvcrucible.trace/v1alpha1"
        or not isinstance(provenance.get("rustc"), str)
        or not isinstance(provenance.get("cargo"), str)
    ):
        raise MediaError("visual evidence provenance boundary differs")

    verdicts = _list(evidence.get("verdicts"), label="verdict evidence")
    if verdicts != EXPECTED_VERDICTS:
        raise MediaError("reviewed verdict evidence differs")

    quality = _dict(evidence.get("quality_gate"), label="quality gate")
    expected_quality = {
        "clippy": "pass",
        "dynamic_dependencies": "absent",
        "dynamic_interpreter": "absent",
        "format": "pass",
        "static_musl_release": "pass",
    }
    if any(quality.get(key) != value for key, value in expected_quality.items()):
        raise MediaError("quality-gate boundary differs")
    tests = _dict(quality.get("tests"), label="test totals")
    if set(tests) != {"failed", "filtered", "ignored", "measured", "passed"}:
        raise MediaError("test-total field set differs")
    for key in tests:
        _int(tests[key], label=f"test total {key}")
    if _int(tests["passed"], label="passed tests") <= 0 or _int(
        tests["failed"], label="failed tests"
    ):
        raise MediaError("quality-gate tests are not a clean pass")

    transcript = sources[TRANSCRIPT_PATH]
    if (
        len(transcript) > MAX_SOURCE_BYTES
        or not transcript.endswith(b"\n")
        or b"\r" in transcript
        or b"\x00" in transcript
        or b"\x1b" in transcript
    ):
        raise MediaError("terminal transcript violates its byte contract")
    try:
        text = transcript.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise MediaError("terminal transcript is not UTF-8") from error
    lines = text.splitlines()
    if len(lines) < 10 or lines[:4] != [
        "KVCrucible verified local evidence",
        "fixture-kind: synthetic",
        "scope: offline bounded traces; no production engine or GPU is exercised",
        (
            "capture-format: exact contract/example stdout; normalized "
            "quality-gate outcomes; successful stderr omitted"
        ),
    ]:
        raise MediaError("terminal transcript provenance header differs")
    if lines[4] != f"toolchain: {provenance['rustc']}":
        raise MediaError("terminal transcript toolchain differs")

    captures = _dict(evidence.get("captures"), label="captures")
    fault_command = "cargo run --quiet --example fault_materialization"
    verdict_command = "cargo run --quiet --example verdict_matrix"
    fault_capture = _capture(captures, "fault", fault_command)
    verdict_capture = _capture(captures, "verdicts", verdict_command)
    fault_stdout = _section(lines, fault_command)
    verdict_stdout = _section(lines, verdict_command)
    for name, record, stdout in (
        ("fault", fault_capture, fault_stdout),
        ("verdicts", verdict_capture, verdict_stdout),
    ):
        digest = _str(record.get("stdout_sha256"), label=f"{name} stdout digest")
        if LOWER_SHA256.fullmatch(digest) is None or digest != _sha256(stdout):
            raise MediaError(f"{name} transcript digest differs")

    expected_fault_lines = [
        "e2#0 Buffered",
        "e0#0 Applied",
        "e1#0 Applied",
        "e1#1 Duplicate",
        "certainty=Exact frontier=Some(2) keys=3",
        "verdict=Converged pristine_deliveries=3 faulted_deliveries=4",
    ]
    fault_lines = fault_stdout.decode("utf-8").splitlines()
    if fault_lines != expected_fault_lines:
        raise MediaError("fault transcript facts differ")

    try:
        transcript_verdicts = json.loads(
            verdict_stdout,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MediaError("verdict transcript stdout is not valid JSON") from error
    if transcript_verdicts != verdicts:
        raise MediaError("verdict transcript is not bound to visual evidence")

    commands = {
        "format": "cargo fmt --all --check",
        "clippy": "cargo clippy --all-targets --all-features --locked -- -D warnings",
        "tests": (
            "cargo test --all-targets --all-features --locked -- "
            "--test-threads=1"
        ),
        "release": (
            "cargo build --release --target "
            "x86_64-unknown-linux-musl --locked"
        ),
        "linkage": (
            "readelf --program-headers --dynamic --wide "
            "target/x86_64-unknown-linux-musl/release/kvcrucible"
        ),
    }
    for name, command in commands.items():
        record = _capture(captures, name, command)
        if name == "tests":
            normalized = (
                f"passed={tests['passed']};failed={tests['failed']};"
                f"ignored={tests['ignored']};measured={tests['measured']};"
                f"filtered={tests['filtered']}"
            )
            if (
                record.get("normalized_result") != normalized
                or record.get("normalized_result_sha256")
                != _sha256(normalized.encode("utf-8"))
            ):
                raise MediaError("normalized test capture differs")
        elif record.get("result") != "pass":
            raise MediaError(f"{name} capture is not a pass")

    gate_lines = [
        f"$ {commands['format']}",
        "PASS",
        f"$ {commands['clippy']}",
        "PASS",
        f"$ {commands['tests']}",
        (
            f"PASS: {tests['passed']} passed, {tests['failed']} failed, "
            f"{tests['ignored']} ignored"
        ),
        f"$ {commands['release']}",
        "PASS",
        f"$ {commands['linkage']}",
        "PASS: no INTERP program header or DT_NEEDED entry",
    ]
    if lines[-len(gate_lines) :] != gate_lines:
        raise MediaError("normalized transcript quality-gate tail differs")

    for visible_line in [f"$ {fault_command}", *fault_lines, *gate_lines]:
        missing = sorted(set(visible_line) - set(FONT))
        if missing:
            raise MediaError(f"visible transcript has unsupported glyphs: {missing!r}")

    return {
        "evidence": cast(JSONValue, evidence),
        "fault_lines": cast(JSONValue, fault_lines),
        "gate_lines": cast(JSONValue, gate_lines),
        "verdicts": cast(JSONValue, verdicts),
    }


def _frame_facts(validated: dict[str, JSONValue]) -> list[dict[str, JSONValue]]:
    fault_lines = [
        _str(item, label="fault line")
        for item in _list(validated["fault_lines"], label="fault lines")
    ]
    deliveries: list[JSONValue] = []
    for line in fault_lines[:4]:
        identity, disposition = line.rsplit(" ", 1)
        deliveries.append({"delivery": identity, "disposition": disposition})

    fold_match = re.fullmatch(
        r"certainty=([A-Za-z]+) frontier=Some\((\d+)\) keys=(\d+)",
        fault_lines[4],
    )
    verdict_match = re.fullmatch(
        r"verdict=([A-Za-z]+) pristine_deliveries=(\d+) "
        r"faulted_deliveries=(\d+)",
        fault_lines[5],
    )
    if fold_match is None or verdict_match is None:
        raise MediaError("fault transcript result cannot be parsed")

    verdicts = [
        _dict(item, label="verdict row")
        for item in _list(validated["verdicts"], label="verdicts")
    ]
    evidence = _dict(validated["evidence"], label="evidence")
    provenance = _dict(evidence["provenance"], label="provenance")
    facts: list[dict[str, JSONValue]] = [
        {
            "deliveries": deliveries,
            "stage": FRAME_STAGES[0],
        },
        {
            "faulted_deliveries": int(verdict_match.group(3)),
            "fold": {
                "certainty": fold_match.group(1),
                "frontier": int(fold_match.group(2)),
                "keys": int(fold_match.group(3)),
            },
            "pristine_deliveries": int(verdict_match.group(2)),
            "stage": FRAME_STAGES[1],
            "verdict": verdict_match.group(1),
        },
        {"row": verdicts[0], "stage": FRAME_STAGES[2]},
        {"row": verdicts[1], "stage": FRAME_STAGES[3]},
        {"row": verdicts[2], "stage": FRAME_STAGES[4]},
        {
            "fixture_kind": provenance["fixture_kind"],
            "fixture_scope": provenance["fixture_scope"],
            "rule": "Unknown evidence is not Diverged",
            "stage": FRAME_STAGES[5],
            "verdicts": [
                {"fixture": row["fixture"], "verdict": row["verdict"]}
                for row in verdicts
            ],
        },
    ]
    if [item["stage"] for item in facts] != list(FRAME_STAGES):
        raise MediaError("frame stage order differs")
    return facts


def _canvas() -> bytearray:
    return bytearray([BACKGROUND]) * (WIDTH * HEIGHT)


def _rect(
    pixels: bytearray,
    x: int,
    y: int,
    width: int,
    height: int,
    color: int,
) -> None:
    if (
        x < 0
        or y < 0
        or width < 0
        or height < 0
        or x + width > WIDTH
        or y + height > HEIGHT
        or not 0 <= color < len(PALETTE)
    ):
        raise MediaError("rectangle exceeds the fixed canvas")
    row = bytes([color]) * width
    for offset_y in range(y, y + height):
        start = offset_y * WIDTH + x
        pixels[start : start + width] = row


def _text_width(text: str, scale: int = 2) -> int:
    return len(text) * 6 * scale


def _text(
    pixels: bytearray,
    x: int,
    y: int,
    value: str,
    color: int,
    *,
    scale: int = 2,
) -> None:
    if scale not in (1, 2, 3) or x < 0 or y < 0:
        raise MediaError("text placement is invalid")
    if x + _text_width(value, scale) > WIDTH or y + 7 * scale > HEIGHT:
        raise MediaError(f"text exceeds the fixed canvas: {value!r}")
    cursor = x
    for character in value:
        rows = FONT.get(character)
        if rows is None:
            raise MediaError(f"unsupported visible glyph: {character!r}")
        for row_index, row in enumerate(rows):
            for column in range(5):
                if row & (1 << (4 - column)):
                    _rect(
                        pixels,
                        cursor + column * scale,
                        y + row_index * scale,
                        scale,
                        scale,
                        color,
                    )
        cursor += 6 * scale


def _palette_bytes() -> bytes:
    return bytes(component for color in PALETTE for component in color)


def _rgb_bytes(indices: bytes | bytearray) -> bytes:
    palette = PALETTE
    output = bytearray(len(indices) * 3)
    cursor = 0
    for index in indices:
        red, green, blue = palette[index]
        output[cursor : cursor + 3] = bytes((red, green, blue))
        cursor += 3
    return bytes(output)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    if len(kind) != 4:
        raise MediaError("PNG chunk type length differs")
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _adler32(data: bytes) -> int:
    first = 1
    second = 0
    modulus = 65521
    for start in range(0, len(data), 5552):
        for value in data[start : start + 5552]:
            first += value
            second += first
        first %= modulus
        second %= modulus
    return (second << 16) | first


def _stored_zlib(data: bytes) -> bytes:
    output = bytearray(b"\x78\x01")
    if not data:
        blocks = [b""]
    else:
        blocks = [data[index : index + 65535] for index in range(0, len(data), 65535)]
    for index, block in enumerate(blocks):
        output.append(1 if index == len(blocks) - 1 else 0)
        length = len(block)
        output.extend(struct.pack("<HH", length, 0xFFFF ^ length))
        output.extend(block)
    output.extend(struct.pack(">I", _adler32(data)))
    return bytes(output)


def _render_png(
    sources: Mapping[str, bytes],
    validated: dict[str, JSONValue],
) -> tuple[bytes, bytes]:
    fault_lines = [
        _str(item, label="fault line")
        for item in _list(validated["fault_lines"], label="fault lines")
    ]
    gate_lines = [
        _str(item, label="gate line")
        for item in _list(validated["gate_lines"], label="gate lines")
    ]
    display_lines = [
        "$ cargo run --quiet --example fault_materialization",
        *fault_lines,
        "",
        *gate_lines,
    ]

    pixels = _canvas()
    _rect(pixels, 30, 24, 1380, 772, PANEL)
    _rect(pixels, 30, 24, 1380, 106, PANEL_ALT)
    _rect(pixels, 30, 24, 10, 106, CYAN)
    _text(pixels, 66, 46, "KVCRUCIBLE VERIFIED EXECUTABLE TRANSCRIPT", TEXT, scale=3)
    _text(pixels, 68, 91, DISCLAIMER, AMBER, scale=1)

    _rect(pixels, 62, 154, 1316, 510, BACKGROUND)
    _rect(pixels, 62, 154, 8, 510, CYAN)
    _text(pixels, 92, 177, "EXACT FAULT STDOUT AND LABELED NORMALIZED GATES", MUTED, scale=1)
    y = 210
    for line in display_lines:
        color = TEXT
        if line.startswith("$ "):
            color = CYAN
        elif line.startswith("PASS"):
            color = GREEN
        elif line.endswith("Buffered") or line.endswith("Duplicate"):
            color = PURPLE
        elif line.startswith("verdict=Converged"):
            color = GREEN
        _text(pixels, 92, y, line, color, scale=2)
        y += 24

    transcript_digest = _sha256(sources[TRANSCRIPT_PATH])
    evidence_digest = _sha256(sources[EVIDENCE_PATH])
    _text(
        pixels,
        66,
        704,
        f"TRANSCRIPT SHA256={transcript_digest[:16]} | EVIDENCE SHA256={evidence_digest[:16]}",
        MUTED,
        scale=1,
    )
    _text(
        pixels,
        66,
        744,
        "FULL TEXT AND MACHINE-READABLE FACTS: docs/visuals/generated/",
        MUTED,
        scale=1,
    )
    _text(pixels, 66, 776, DISCLAIMER, AMBER, scale=1)

    packed_rows = bytearray()
    for row_index in range(HEIGHT):
        packed_rows.append(0)
        start = row_index * WIDTH
        row = pixels[start : start + WIDTH]
        for index in range(0, WIDTH, 2):
            packed_rows.append((row[index] << 4) | row[index + 1])

    metadata = (
        ("ClaimBoundary", "executable-derived-synthetic-fixture"),
        ("Description", DISCLAIMER),
        ("EvidenceSHA256", evidence_digest),
        ("TranscriptSHA256", transcript_digest),
        ("Title", "KVCrucible verified executable transcript"),
    )
    chunks = [
        _png_chunk(
            b"IHDR",
            struct.pack(">IIBBBBB", WIDTH, HEIGHT, 4, 3, 0, 0, 0),
        ),
        _png_chunk(b"PLTE", _palette_bytes()),
    ]
    chunks.extend(
        _png_chunk(
            b"tEXt",
            key.encode("latin-1") + b"\x00" + value.encode("latin-1"),
        )
        for key, value in metadata
    )
    chunks.extend(
        (
            _png_chunk(b"IDAT", _stored_zlib(bytes(packed_rows))),
            _png_chunk(b"IEND", b""),
        )
    )
    body = b"\x89PNG\r\n\x1a\n" + b"".join(chunks)
    if len(body) > MAX_OUTPUT_BYTES:
        raise MediaError("PNG exceeds its byte budget")
    return body, bytes(pixels)


def _gif_subblocks(payload: bytes) -> bytes:
    output = bytearray()
    for index in range(0, len(payload), 255):
        block = payload[index : index + 255]
        output.append(len(block))
        output.extend(block)
    output.append(0)
    return bytes(output)


def _gif_comment(payload: bytes) -> bytes:
    return b"\x21\xfe" + _gif_subblocks(payload)


def _lzw_encode(indices: bytes) -> bytes:
    if not indices or any(index >= 16 for index in indices):
        raise MediaError("GIF indices violate the fixed palette")
    minimum = 4
    clear = 1 << minimum
    end = clear + 1
    next_code = end + 1
    code_size = minimum + 1
    table: dict[tuple[int, int], int] = {}
    emitted: list[tuple[int, int]] = [(clear, code_size)]
    prefix = indices[0]

    for symbol in indices[1:]:
        key = (prefix, symbol)
        known = table.get(key)
        if known is not None:
            prefix = known
            continue
        emitted.append((prefix, code_size))
        if next_code < 4096:
            table[key] = next_code
            next_code += 1
            if next_code > (1 << code_size) and code_size < 12:
                code_size += 1
        else:
            emitted.append((clear, code_size))
            table.clear()
            next_code = end + 1
            code_size = minimum + 1
        prefix = symbol
    emitted.append((prefix, code_size))
    emitted.append((end, code_size))

    accumulator = 0
    bit_count = 0
    packed = bytearray()
    for code, width in emitted:
        if code >= 1 << width:
            raise MediaError("GIF LZW code exceeds its current width")
        accumulator |= code << bit_count
        bit_count += width
        while bit_count >= 8:
            packed.append(accumulator & 0xFF)
            accumulator >>= 8
            bit_count -= 8
    if bit_count:
        packed.append(accumulator & 0xFF)
    return bytes((minimum,)) + _gif_subblocks(bytes(packed))


def _execution_lines(execution: dict[str, JSONValue]) -> tuple[str, ...]:
    return (
        f"CERTAINTY={_str(execution['certainty'], label='certainty').upper()}",
        (
            f"FRONTIER={_int(execution['frontier'], label='frontier')} | "
            f"KEYS={_int(execution['keys'], label='keys')}"
        ),
        (
            "DELIVERIES="
            f"{_int(execution['processed_deliveries'], label='deliveries')} | "
            f"STALE={_int(execution['stale_unverifiable'], label='stale')}"
        ),
        (
            "FP WINDOW="
            f"{_int(execution['fingerprint_window'], label='fingerprint window')}"
        ),
    )


def _frame_panels(
    stage_index: int,
    facts: dict[str, JSONValue],
) -> tuple[str, str, list[tuple[str, int, tuple[str, ...]]], str, int]:
    if stage_index == 0:
        raw = [
            _dict(item, label="delivery")
            for item in _list(facts["deliveries"], label="deliveries")
        ]
        title = "EXECUTED FAULT SCHEDULE"
        subtitle = "EXACT DISPOSITIONS FROM fault_materialization STDOUT"
        panels = [
            (
                "FAULTED DELIVERY 1-2",
                CYAN,
                tuple(
                    f"{_str(item['delivery'], label='delivery').upper()} "
                    f"{_str(item['disposition'], label='disposition').upper()}"
                    for item in raw[:2]
                ),
            ),
            (
                "FAULTED DELIVERY 3-4",
                PURPLE,
                tuple(
                    f"{_str(item['delivery'], label='delivery').upper()} "
                    f"{_str(item['disposition'], label='disposition').upper()}"
                    for item in raw[2:]
                ),
            ),
        ]
        outcome, color = "BUFFERING AND DUPLICATION ARE OBSERVED, NOT SIMULATED UI", CYAN
    elif stage_index == 1:
        fold = _dict(facts["fold"], label="fold result")
        title = "FAULT MATERIALIZATION RESULT"
        subtitle = "THE EXECUTED EXAMPLE REACHES ONE ELIGIBLE COMPARISON"
        panels = [
            (
                "FAULTED FOLD",
                PURPLE,
                (
                    f"CERTAINTY={_str(fold['certainty'], label='certainty').upper()}",
                    (
                        f"FRONTIER={_int(fold['frontier'], label='frontier')} | "
                        f"KEYS={_int(fold['keys'], label='keys')}"
                    ),
                ),
            ),
            (
                "DELIVERY COUNTS",
                CYAN,
                (
                    f"PRISTINE={_int(facts['pristine_deliveries'], label='pristine deliveries')}",
                    f"FAULTED={_int(facts['faulted_deliveries'], label='faulted deliveries')}",
                ),
            ),
        ]
        outcome = f"VERDICT={_str(facts['verdict'], label='verdict').upper()}"
        color = GREEN
    elif stage_index in (2, 3, 4):
        row = _dict(facts["row"], label="verdict row")
        verdict = _str(row["verdict"], label="verdict")
        title = f"{verdict.upper()} VERDICT"
        subtitle = (
            f"FIXTURE={_str(row['fixture'], label='fixture').removeprefix('synthetic/').upper()} "
            f"| SCHEDULE={_str(row['schedule'], label='schedule').upper()}"
        )
        panels = [
            (
                "PRISTINE",
                CYAN,
                _execution_lines(_dict(row["pristine"], label="pristine")),
            ),
            (
                "FAULTED",
                PURPLE,
                _execution_lines(_dict(row["faulted"], label="faulted")),
            ),
        ]
        reasons = _dict(row["ineligibility"], label="ineligibility")
        if verdict == "Ineligible":
            outcome = (
                "FAULTED INEXACT=TRUE | FRONTIER MISMATCH=TRUE | "
                "EVIDENCE CANNOT DECIDE"
            )
            color = AMBER
        elif verdict == "Diverged":
            outcome = (
                "BOTH EXACT AT FRONTIER 0 | WINDOW=0 | "
                "PRISTINE STALE=1 | DIVERGED"
            )
            color = RED
        else:
            outcome = "BOTH EXACT AT FRONTIER 2 | ELIGIBLE VIEW MATCH | CONVERGED"
            color = GREEN
        if verdict != "Ineligible" and any(
            _bool(reasons[key], label=f"ineligibility {key}")
            for key in ("pristine_inexact", "faulted_inexact", "frontier_mismatch")
        ):
            raise MediaError("eligible verdict has an ineligibility reason")
    elif stage_index == 5:
        title = "DECISION BOUNDARY"
        subtitle = "THREE EXECUTED SYNTHETIC FIXTURES | NO PRODUCTION ENGINE OR GPU"
        rows = [
            _dict(item, label="boundary verdict")
            for item in _list(facts["verdicts"], label="boundary verdicts")
        ]
        colors = (GREEN, RED, AMBER)
        panels = [
            (
                _str(row["verdict"], label="boundary verdict").upper(),
                color,
                (
                    _str(row["fixture"], label="boundary fixture")
                    .removeprefix("synthetic/")
                    .upper(),
                    "EXECUTABLE-DERIVED",
                ),
            )
            for row, color in zip(rows, colors, strict=True)
        ]
        outcome = "UNKNOWN EVIDENCE IS NOT DIVERGED | INELIGIBLE FAILS CLOSED"
        color = AMBER
    else:
        raise MediaError("unsupported frame stage")
    return title, subtitle, panels, outcome, color


def _render_frame(stage_index: int, facts: dict[str, JSONValue]) -> bytes:
    pixels = _canvas()
    _rect(pixels, 30, 24, 1380, 772, PANEL)
    _rect(pixels, 30, 24, 1380, 104, PANEL_ALT)
    _rect(pixels, 30, 24, 10, 104, CYAN)
    title, subtitle, panels, outcome, outcome_color = _frame_panels(
        stage_index,
        facts,
    )
    _text(pixels, 66, 44, f"{stage_index + 1}/6 {title}", TEXT, scale=3)
    _text(pixels, 68, 88, subtitle, MUTED, scale=1)

    for index in range(6):
        color = (
            GREEN
            if index < stage_index
            else CYAN
            if index == stage_index
            else LINE
        )
        _rect(pixels, 66 + index * 218, 142, 190, 8, color)

    count = len(panels)
    if count == 2:
        positions = ((66, 640), (734, 640))
    elif count == 3:
        positions = ((50, 420), (510, 420), (970, 420))
    else:
        raise MediaError("frame panel count differs")
    for (heading, accent, lines), (x, width) in zip(
        panels,
        positions,
        strict=True,
    ):
        _rect(pixels, x, 184, width, 410, PANEL_ALT)
        _rect(pixels, x, 184, width, 9, accent)
        _text(pixels, x + 28, 220, heading, accent, scale=2)
        y = 286
        for line in lines:
            _text(pixels, x + 28, y, line, TEXT, scale=2)
            y += 68
        _text(
            pixels,
            x + 28,
            560,
            f"STAGE={FRAME_STAGES[stage_index].upper()}",
            MUTED,
            scale=1,
        )

    _rect(pixels, 66, 626, 1308, 76, BACKGROUND)
    _rect(pixels, 66, 626, 8, 76, outcome_color)
    _text(pixels, 94, 654, outcome, outcome_color, scale=2)
    _text(pixels, 66, 738, DISCLAIMER, AMBER, scale=1)
    _text(
        pixels,
        66,
        772,
        "FACTS: terminal-transcript.txt AND visual-evidence.json",
        MUTED,
        scale=1,
    )
    return bytes(pixels)


def _render_gif(
    validated: dict[str, JSONValue],
) -> tuple[bytes, list[bytes], list[dict[str, JSONValue]]]:
    facts = _frame_facts(validated)
    frames = [
        _render_frame(index, frame_facts)
        for index, frame_facts in enumerate(facts)
    ]

    body = bytearray(b"GIF89a")
    body.extend(struct.pack("<HHBBB", WIDTH, HEIGHT, 0xB3, BACKGROUND, 0))
    body.extend(_palette_bytes())
    body.extend(_gif_comment(DISCLAIMER.encode("ascii")))
    for frame, delay, frame_facts in zip(
        frames,
        FRAME_DELAYS_CS,
        facts,
        strict=True,
    ):
        comment = FRAME_COMMENT_PREFIX + _canonical(
            cast(JSONValue, frame_facts)
        )
        body.extend(_gif_comment(comment))
        body.extend(b"\x21\xf9\x04\x04")
        body.extend(struct.pack("<H", delay))
        body.extend(b"\x00\x00")
        body.append(0x2C)
        body.extend(struct.pack("<HHHHB", 0, 0, WIDTH, HEIGHT, 0))
        body.extend(_lzw_encode(frame))
    body.append(0x3B)
    result = bytes(body)
    if len(result) > MAX_OUTPUT_BYTES:
        raise MediaError("GIF exceeds its byte budget")
    return result, frames, facts


def render_media(sources: Mapping[str, bytes]) -> dict[str, bytes]:
    """Render a closed deterministic media candidate entirely in memory."""

    validated = _validate_sources(sources)
    png, png_pixels = _render_png(sources, validated)
    gif, gif_frames, frame_facts = _render_gif(validated)
    palette = _palette_bytes()

    frame_records: list[JSONValue] = []
    for stage, delay, pixels, facts in zip(
        FRAME_STAGES,
        FRAME_DELAYS_CS,
        gif_frames,
        frame_facts,
        strict=True,
    ):
        frame_records.append(
            {
                "delay_cs": delay,
                "facts": facts,
                "facts_sha256": _sha256(
                    _canonical(cast(JSONValue, facts))
                ),
                "index_sha256": _sha256(pixels),
                "rgb_sha256": _sha256(_rgb_bytes(pixels)),
                "stage": stage,
            }
        )

    input_records: list[JSONValue] = [
        {
            "bytes": len(sources[path]),
            "path": path,
            "sha256": _sha256(sources[path]),
        }
        for path in EVIDENCE_PATHS
    ]
    tool_records: list[JSONValue] = [
        {
            "bytes": len(sources[path]),
            "path": path,
            "sha256": _sha256(sources[path]),
        }
        for path in TOOL_PATHS
    ]
    source_hashes: dict[str, JSONValue] = {
        "evidence": _sha256(sources[EVIDENCE_PATH]),
        "transcript": _sha256(sources[TRANSCRIPT_PATH]),
    }
    output_records: list[JSONValue] = [
        {
            "bytes": len(gif),
            "frame_count": len(gif_frames),
            "frames": frame_records,
            "height": HEIGHT,
            "media_type": "image/gif",
            "palette_sha256": _sha256(palette),
            "path": GIF_NAME,
            "playback": "once",
            "sha256": _sha256(gif),
            "width": WIDTH,
        },
        {
            "bytes": len(png),
            "height": HEIGHT,
            "index_sha256": _sha256(png_pixels),
            "media_type": "image/png",
            "palette_sha256": _sha256(palette),
            "path": PNG_NAME,
            "rgb_sha256": _sha256(_rgb_bytes(png_pixels)),
            "sha256": _sha256(png),
            "source_sha256": source_hashes,
            "width": WIDTH,
        },
    ]
    manifest_record: dict[str, JSONValue] = {
        "claim_boundary": cast(JSONValue, CLAIM_BOUNDARY),
        "disclaimer": DISCLAIMER,
        "freshness_gate": "python3 tools/render_readme_visuals.py --check",
        "inputs": input_records,
        "outputs": output_records,
        "schema": MANIFEST_SCHEMA,
        "tools": tool_records,
    }
    manifest = _canonical(cast(JSONValue, manifest_record)) + b"\n"
    result = {GIF_NAME: gif, MANIFEST_NAME: manifest, PNG_NAME: png}
    if (
        tuple(sorted(result)) != EXPECTED_OUTPUTS
        or any(
            not body or len(body) > MAX_OUTPUT_BYTES
            for body in result.values()
        )
        or sum(map(len, result.values())) > MAX_TOTAL_OUTPUT_BYTES
    ):
        raise MediaError("rendered media inventory violates its byte contract")
    return result


def _stable_stat(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_relative(root: Path, relative: str) -> bytes:
    parts = Path(relative).parts
    if (
        not parts
        or Path(relative).is_absolute()
        or ".." in parts
        or Path(relative).as_posix() != relative
    ):
        raise MediaError(f"unsafe repository path: {relative}")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        current = descriptor
        opened: list[int] = []
        try:
            for part in parts[:-1]:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=current,
                )
                opened.append(child)
                current = child
            file_descriptor = os.open(
                parts[-1],
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            try:
                metadata = os.fstat(file_descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or metadata.st_size <= 0
                    or metadata.st_size > MAX_SOURCE_BYTES
                ):
                    raise MediaError(f"source file contract differs: {relative}")
                chunks: list[bytes] = []
                remaining = metadata.st_size
                while remaining:
                    chunk = os.read(file_descriptor, min(65536, remaining))
                    if not chunk:
                        raise MediaError(f"source file was truncated: {relative}")
                    chunks.append(chunk)
                    remaining -= len(chunk)
                if os.read(file_descriptor, 1):
                    raise MediaError(f"source file grew while being read: {relative}")
                if _stable_stat(os.fstat(file_descriptor)) != _stable_stat(metadata):
                    raise MediaError(f"source file changed while being read: {relative}")
                return b"".join(chunks)
            finally:
                os.close(file_descriptor)
        finally:
            for opened_descriptor in reversed(opened):
                os.close(opened_descriptor)
    finally:
        os.close(descriptor)


def load_sources(repository: Path) -> dict[str, bytes]:
    root = repository.resolve(strict=True)
    if not root.is_dir():
        raise MediaError("repository root is not a directory")
    return {path: _read_relative(root, path) for path in SOURCE_PATHS}


def _git(repository: Path, arguments: Sequence[str]) -> bytes:
    try:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=repository,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise MediaError("Git provenance command failed") from error
    if completed.returncode != 0 or completed.stderr:
        raise MediaError("Git provenance command failed")
    return completed.stdout


def validate_checkout(repository: Path, expected_revision: str) -> Path:
    if LOWER_GIT_SHA.fullmatch(expected_revision) is None:
        raise MediaError("expected revision must be a full lowercase Git SHA")
    root = repository.resolve(strict=True)
    top = _git(root, ("rev-parse", "--show-toplevel")).decode("utf-8", errors="strict").strip()
    if Path(top).resolve(strict=True) != root:
        raise MediaError("repository argument is not the physical Git root")
    head = _git(root, ("rev-parse", "HEAD")).decode("ascii", errors="strict").strip()
    if head != expected_revision:
        raise MediaError("checked-out revision differs from the expected revision")
    status = _git(
        root,
        ("status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=none"),
    )
    if status:
        raise MediaError("candidate checkout is not clean")
    return root


def _write_candidate(directory: Path, outputs: Mapping[str, bytes]) -> None:
    if tuple(sorted(outputs)) != EXPECTED_OUTPUTS:
        raise MediaError("candidate output inventory differs")
    parent = directory.parent.resolve(strict=True)
    name = directory.name
    if not name or name in (".", "..") or directory.is_absolute() is False:
        raise MediaError("candidate output directory must be an absolute new path")
    parent_fd = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    directory_fd = -1
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        directory_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        for output_name in (GIF_NAME, PNG_NAME, MANIFEST_NAME):
            data = outputs[output_name]
            descriptor = os.open(
                output_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory_fd,
            )
            try:
                offset = 0
                while offset < len(data):
                    written = os.write(descriptor, data[offset:])
                    if written <= 0:
                        raise MediaError("candidate output write made no progress")
                    offset += written
                os.fchmod(descriptor, 0o644)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.fsync(directory_fd)
        observed = tuple(sorted(os.listdir(directory_fd)))
        if observed != EXPECTED_OUTPUTS:
            raise MediaError("published candidate inventory differs")
    except BaseException:
        if directory_fd >= 0:
            for output_name in EXPECTED_OUTPUTS:
                try:
                    os.unlink(output_name, dir_fd=directory_fd)
                except OSError:
                    pass
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
        os.close(parent_fd)


def _read_media_directory(directory: Path) -> dict[str, bytes]:
    if directory.is_symlink():
        raise MediaError("media directory cannot be a symbolic link")
    try:
        root = directory.resolve(strict=True)
        if not root.is_dir():
            raise MediaError("media directory is not a directory")
        observed = tuple(sorted(entry.name for entry in os.scandir(root)))
        if observed != EXPECTED_OUTPUTS:
            raise MediaError("media directory inventory is not closed")
        return {name: _read_relative(root, name) for name in EXPECTED_OUTPUTS}
    except OSError as error:
        raise MediaError("media directory cannot be read safely") from error


def check_committed(repository: Path, media_directory: Path) -> None:
    sources = load_sources(repository)
    committed = _read_media_directory(media_directory)
    expected = render_media(sources)
    if load_sources(repository) != sources:
        raise MediaError("README media sources changed during committed check")
    if committed != expected:
        raise MediaError("committed README media differs from deterministic rendering")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render deterministic evidence-derived KVCrucible README media"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    candidate = commands.add_parser("candidate")
    candidate.add_argument("--repository", required=True, type=Path)
    candidate.add_argument("--expected-revision", required=True)
    candidate.add_argument("--output-directory", required=True, type=Path)
    check = commands.add_parser("check")
    check.add_argument("--repository", required=True, type=Path)
    check.add_argument("--media-directory", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "candidate":
            repository = validate_checkout(
                cast(Path, arguments.repository),
                cast(str, arguments.expected_revision),
            )
            sources = load_sources(repository)
            outputs = render_media(sources)
            if load_sources(repository) != sources:
                raise MediaError("README media sources changed during rendering")
            _write_candidate(cast(Path, arguments.output_directory), outputs)
            if load_sources(repository) != sources:
                raise MediaError("README media sources changed during publication")
            if _git(
                repository,
                (
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=normal",
                    "--ignore-submodules=none",
                ),
            ):
                raise MediaError("candidate rendering changed the checkout")
            print(
                _canonical(
                    {
                        "outputs": [
                            {
                                "bytes": len(outputs[name]),
                                "path": name,
                                "sha256": _sha256(outputs[name]),
                            }
                            for name in EXPECTED_OUTPUTS
                        ],
                        "checkout_revision": cast(str, arguments.expected_revision),
                        "status": "ok",
                    }
                ).decode("ascii")
            )
            return 0
        if arguments.command == "check":
            check_committed(
                cast(Path, arguments.repository),
                cast(Path, arguments.media_directory),
            )
            print("verified 3 committed README media artifacts")
            return 0
        raise MediaError("unsupported command")
    except (MediaError, OSError, UnicodeError) as error:
        message = " ".join(str(error).split())[:512]
        print(f"README media error: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
