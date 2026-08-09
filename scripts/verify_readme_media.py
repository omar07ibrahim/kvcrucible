from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import stat
import struct
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Final, TypeAlias, cast

WIDTH: Final = 1440
HEIGHT: Final = 820
PNG_NAME: Final = "terminal-transcript.png"
GIF_NAME: Final = "verdict-fault-workflow.gif"
MANIFEST_NAME: Final = "manifest.sha256.json"
EXPECTED_MEDIA_FILES: Final = (MANIFEST_NAME, PNG_NAME, GIF_NAME)
EXPECTED_PRODUCTION_SHA256: Final[dict[str, str]] = {}
MANIFEST_SCHEMA: Final = "kvcrucible.readme-media-manifest/v1"
EVIDENCE_SCHEMA: Final = "kvcrucible.visual-evidence/v2"
DISCLAIMER: Final = (
    "EVIDENCE-DERIVED | SYNTHETIC OFFLINE FIXTURE | "
    "NOT OS CAPTURE | NOT BENCHMARK"
)
FRAME_COMMENT_PREFIX: Final = b"KVCRUCIBLE-FRAME-V1\x00"
MAX_SOURCE_BYTES: Final = 512 * 1024
MAX_MEDIA_BYTES: Final = 2 * 1024 * 1024
MAX_TOTAL_MEDIA_BYTES: Final = 4 * 1024 * 1024
MAX_PNG_CHUNKS: Final = 16
MAX_GIF_BLOCK_BYTES: Final = 2 * 1024 * 1024
MAX_GIF_CODES: Final = WIDTH * HEIGHT * 2
TRANSCRIPT_PATH: Final = "docs/visuals/generated/terminal-transcript.txt"
EVIDENCE_PATH: Final = "docs/visuals/generated/visual-evidence.json"
GENERATOR_PATH: Final = "tools/render_readme_media.py"
AUDITOR_PATH: Final = "scripts/verify_readme_media.py"
EVIDENCE_PATHS: Final = tuple(sorted((EVIDENCE_PATH, TRANSCRIPT_PATH)))
TOOL_PATHS: Final = tuple(sorted((AUDITOR_PATH, GENERATOR_PATH)))
SOURCE_PATHS: Final = tuple(sorted((*EVIDENCE_PATHS, *TOOL_PATHS)))
FRAME_STAGES: Final = (
    "fault-schedule",
    "fault-result",
    "converged",
    "diverged",
    "ineligible",
    "decision-boundary",
)
FRAME_DELAYS_CS: Final = (140, 160, 180, 200, 220, 300)
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
LOWER_SHA256: Final = frozenset("0123456789abcdef")

JSONScalar: TypeAlias = bool | int | str | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


class AuditError(RuntimeError):
    """Raised when a README media candidate fails independent audit."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: JSONValue) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _pairs(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise AuditError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json(
    data: bytes, *, label: str, maximum: int = MAX_SOURCE_BYTES
) -> dict[str, JSONValue]:
    if not data or len(data) > maximum or not data.endswith(b"\n"):
        raise AuditError(f"{label} violates its canonical byte contract")
    try:
        value = json.loads(data, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict) or _canonical(cast(JSONValue, value)) + b"\n" != data:
        raise AuditError(f"{label} is not canonical JSON")
    return cast(dict[str, JSONValue], value)


def _object(value: JSONValue, label: str) -> dict[str, JSONValue]:
    if not isinstance(value, dict):
        raise AuditError(f"{label} must be an object")
    return value


def _array(value: JSONValue, label: str) -> list[JSONValue]:
    if not isinstance(value, list):
        raise AuditError(f"{label} must be an array")
    return value


def _text(value: JSONValue, label: str) -> str:
    if not isinstance(value, str):
        raise AuditError(f"{label} must be a string")
    return value


def _integer(value: JSONValue, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AuditError(f"{label} must be an integer")
    return value


def _boolean(value: JSONValue, label: str) -> bool:
    if not isinstance(value, bool):
        raise AuditError(f"{label} must be a boolean")
    return value


def _digest(value: JSONValue, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or set(result) - LOWER_SHA256:
        raise AuditError(f"{label} is not a lowercase SHA-256")
    return result


def _palette_bytes() -> bytes:
    return bytes(component for color in PALETTE for component in color)


def _rgb_bytes(indices: bytes) -> bytes:
    output = bytearray(len(indices) * 3)
    position = 0
    for index in indices:
        if index >= len(PALETTE):
            raise AuditError("decoded palette index is out of range")
        output[position : position + 3] = bytes(PALETTE[index])
        position += 3
    return bytes(output)


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


def _parse_evidence(data: bytes) -> dict[str, JSONValue]:
    if not data or len(data) > MAX_SOURCE_BYTES or not data.endswith(b"\n"):
        raise AuditError("visual evidence violates its byte contract")
    try:
        value = json.loads(data, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError("visual evidence is invalid JSON") from error
    expected = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    if not isinstance(value, dict) or expected != data:
        raise AuditError("visual evidence is not canonical pretty JSON")
    return cast(dict[str, JSONValue], value)


def _transcript_section(lines: list[str], command: str) -> bytes:
    marker = f"$ {command}"
    positions = [index for index, line in enumerate(lines) if line == marker]
    if len(positions) != 1:
        raise AuditError(f"transcript command is not unique: {command}")
    first = positions[0] + 1
    last = first
    while last < len(lines) and lines[last]:
        last += 1
    if first == last:
        raise AuditError(f"transcript command has no stdout: {command}")
    return ("\n".join(lines[first:last]) + "\n").encode()


def _capture(
    captures: dict[str, JSONValue],
    name: str,
    command: str,
) -> dict[str, JSONValue]:
    record = _object(captures.get(name), f"{name} capture")
    if record.get("command") != command:
        raise AuditError(f"{name} capture command differs")
    return record


def _semantic_sources(sources: Mapping[str, bytes]) -> dict[str, JSONValue]:
    if tuple(sorted(sources)) != SOURCE_PATHS:
        raise AuditError("audited source inventory is not closed")
    if any(not body or len(body) > MAX_SOURCE_BYTES for body in sources.values()):
        raise AuditError("audited source exceeds its byte budget")

    evidence = _parse_evidence(sources[EVIDENCE_PATH])
    if set(evidence) != {
        "captures",
        "contract",
        "provenance",
        "quality_gate",
        "schema",
        "verdicts",
    } or evidence.get("schema") != EVIDENCE_SCHEMA:
        raise AuditError("visual evidence schema or field set differs")
    provenance = _object(evidence.get("provenance"), "provenance")
    if (
        provenance.get("fixture_kind") != "synthetic"
        or provenance.get("fixture_scope")
        != "offline bounded traces; no production engine or GPU is exercised"
        or provenance.get("trace_format") != "kvcrucible.trace/v1alpha1"
    ):
        raise AuditError("evidence provenance boundary differs")

    verdicts = _array(evidence.get("verdicts"), "verdict evidence")
    if verdicts != EXPECTED_VERDICTS:
        raise AuditError("reviewed verdict evidence differs")

    quality = _object(evidence.get("quality_gate"), "quality gate")
    for key, expected in {
        "format": "pass",
        "clippy": "pass",
        "static_musl_release": "pass",
        "dynamic_interpreter": "absent",
        "dynamic_dependencies": "absent",
    }.items():
        if quality.get(key) != expected:
            raise AuditError(f"quality fact differs: {key}")
    tests = _object(quality.get("tests"), "test totals")
    if set(tests) != {"failed", "filtered", "ignored", "measured", "passed"}:
        raise AuditError("test-total field set differs")
    if any(_integer(tests[key], f"test total {key}") < 0 for key in tests):
        raise AuditError("test total is negative")
    if _integer(tests["failed"], "failed tests") != 0 or _integer(
        tests["passed"], "passed tests"
    ) <= 0:
        raise AuditError("test totals are not a clean pass")

    transcript = sources[TRANSCRIPT_PATH]
    if (
        not transcript.endswith(b"\n")
        or b"\r" in transcript
        or b"\x00" in transcript
        or b"\x1b" in transcript
    ):
        raise AuditError("terminal transcript byte contract differs")
    try:
        lines = transcript.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise AuditError("terminal transcript is not UTF-8") from error
    if lines[:4] != [
        "KVCrucible verified local evidence",
        "fixture-kind: synthetic",
        "scope: offline bounded traces; no production engine or GPU is exercised",
        (
            "capture-format: exact contract/example stdout; normalized "
            "quality-gate outcomes; successful stderr omitted"
        ),
    ] or lines[4] != f"toolchain: {provenance['rustc']}":
        raise AuditError("terminal transcript provenance differs")

    captures = _object(evidence.get("captures"), "captures")
    fault_command = "cargo run --quiet --example fault_materialization"
    verdict_command = "cargo run --quiet --example verdict_matrix"
    fault_record = _capture(captures, "fault", fault_command)
    verdict_record = _capture(captures, "verdicts", verdict_command)
    fault_stdout = _transcript_section(lines, fault_command)
    verdict_stdout = _transcript_section(lines, verdict_command)
    for label, record, stdout in (
        ("fault", fault_record, fault_stdout),
        ("verdicts", verdict_record, verdict_stdout),
    ):
        if _sha256(stdout) != _digest(record.get("stdout_sha256"), f"{label} digest"):
            raise AuditError(f"{label} transcript digest differs")

    fault_lines = fault_stdout.decode().splitlines()
    if fault_lines != [
        "e2#0 Buffered",
        "e0#0 Applied",
        "e1#0 Applied",
        "e1#1 Duplicate",
        "certainty=Exact frontier=Some(2) keys=3",
        "verdict=Converged pristine_deliveries=3 faulted_deliveries=4",
    ]:
        raise AuditError("fault transcript facts differ")
    try:
        transcript_verdicts = json.loads(
            verdict_stdout,
            object_pairs_hook=_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditError("verdict stdout is invalid JSON") from error
    if transcript_verdicts != verdicts:
        raise AuditError("transcript verdicts differ from visual evidence")

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
                != _sha256(normalized.encode())
            ):
                raise AuditError("normalized test capture differs")
        elif record.get("result") != "pass":
            raise AuditError(f"{name} capture is not a pass")
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
        raise AuditError("normalized quality-gate transcript tail differs")
    return {
        "evidence": cast(JSONValue, evidence),
        "fault_lines": cast(JSONValue, fault_lines),
        "verdicts": cast(JSONValue, verdicts),
    }


def _expected_facts(validated: dict[str, JSONValue]) -> list[dict[str, JSONValue]]:
    fault_lines = [
        _text(item, "fault line")
        for item in _array(validated["fault_lines"], "fault lines")
    ]
    deliveries: list[JSONValue] = []
    for line in fault_lines[:4]:
        identity, disposition = line.rsplit(" ", 1)
        deliveries.append({"delivery": identity, "disposition": disposition})

    first = fault_lines[4]
    second = fault_lines[5]
    prefix = "certainty="
    middle = " frontier=Some("
    suffix = ") keys="
    if not first.startswith(prefix) or middle not in first or suffix not in first:
        raise AuditError("fault fold line cannot be parsed")
    certainty, tail = first[len(prefix) :].split(middle, 1)
    frontier_text, keys_text = tail.split(suffix, 1)
    verdict_parts = dict(
        field.split("=", 1)
        for field in second.split()
        if "=" in field
    )
    try:
        fold = {
            "certainty": certainty,
            "frontier": int(frontier_text),
            "keys": int(keys_text),
        }
        pristine_deliveries = int(verdict_parts["pristine_deliveries"])
        faulted_deliveries = int(verdict_parts["faulted_deliveries"])
        verdict = verdict_parts["verdict"]
    except (KeyError, ValueError) as error:
        raise AuditError("fault result fields cannot be parsed") from error

    rows = [
        _object(item, "verdict row")
        for item in _array(validated["verdicts"], "verdicts")
    ]
    evidence = _object(validated["evidence"], "evidence")
    provenance = _object(evidence["provenance"], "provenance")
    facts: list[dict[str, JSONValue]] = [
        {"deliveries": deliveries, "stage": FRAME_STAGES[0]},
        {
            "faulted_deliveries": faulted_deliveries,
            "fold": fold,
            "pristine_deliveries": pristine_deliveries,
            "stage": FRAME_STAGES[1],
            "verdict": verdict,
        },
        {"row": rows[0], "stage": FRAME_STAGES[2]},
        {"row": rows[1], "stage": FRAME_STAGES[3]},
        {"row": rows[2], "stage": FRAME_STAGES[4]},
        {
            "fixture_kind": provenance["fixture_kind"],
            "fixture_scope": provenance["fixture_scope"],
            "rule": "Unknown evidence is not Diverged",
            "stage": FRAME_STAGES[5],
            "verdicts": [
                {"fixture": row["fixture"], "verdict": row["verdict"]}
                for row in rows
            ],
        },
    ]
    if [item["stage"] for item in facts] != list(FRAME_STAGES):
        raise AuditError("frame stage order differs")
    return facts


def _adler32(data: bytes) -> int:
    low = 1
    high = 0
    for value in data:
        low = (low + value) % 65521
        high = (high + low) % 65521
    return (high << 16) | low


def _inflate_stored(payload: bytes, expected_size: int) -> bytes:
    if len(payload) < 11 or payload[:2] != b"\x78\x01":
        raise AuditError("PNG IDAT is not canonical stored zlib")
    position = 2
    output = bytearray()
    final = False
    blocks = 0
    while not final:
        if position + 5 > len(payload) - 4 or blocks > 32:
            raise AuditError("PNG stored block header is invalid")
        header = payload[position]
        position += 1
        if header & 0xFE:
            raise AuditError("PNG deflate block is not byte-aligned stored data")
        final = bool(header & 1)
        length, complement = struct.unpack_from("<HH", payload, position)
        position += 4
        if complement != (0xFFFF ^ length) or position + length > len(payload) - 4:
            raise AuditError("PNG stored block length is invalid")
        output.extend(payload[position : position + length])
        position += length
        blocks += 1
        if len(output) > expected_size:
            raise AuditError("PNG inflated data exceeds its exact bound")
    if position != len(payload) - 4:
        raise AuditError("PNG zlib stream has trailing data")
    checksum = struct.unpack_from(">I", payload, position)[0]
    if checksum != _adler32(bytes(output)) or len(output) != expected_size:
        raise AuditError("PNG Adler-32 or inflated length differs")
    return bytes(output)


def parse_png(data: bytes) -> dict[str, JSONValue | bytes]:
    if not data or len(data) > MAX_MEDIA_BYTES or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise AuditError("PNG signature or byte budget differs")
    position = 8
    chunks: list[tuple[bytes, bytes]] = []
    while position < len(data):
        if len(chunks) >= MAX_PNG_CHUNKS or position + 12 > len(data):
            raise AuditError("PNG chunk inventory exceeds its bound")
        length = struct.unpack_from(">I", data, position)[0]
        position += 4
        kind = data[position : position + 4]
        position += 4
        if length > MAX_MEDIA_BYTES or position + length + 4 > len(data):
            raise AuditError("PNG chunk length exceeds its bound")
        payload = data[position : position + length]
        position += length
        expected_crc = struct.unpack_from(">I", data, position)[0]
        position += 4
        if expected_crc != binascii.crc32(kind + payload) & 0xFFFFFFFF:
            raise AuditError("PNG chunk CRC differs")
        chunks.append((kind, payload))
        if kind == b"IEND":
            break
    if position != len(data):
        raise AuditError("PNG has trailing bytes")
    kinds = [kind for kind, _payload in chunks]
    if kinds != [
        b"IHDR",
        b"PLTE",
        b"tEXt",
        b"tEXt",
        b"tEXt",
        b"tEXt",
        b"tEXt",
        b"IDAT",
        b"IEND",
    ]:
        raise AuditError("PNG canonical chunk order differs")
    ihdr = chunks[0][1]
    if len(ihdr) != 13:
        raise AuditError("PNG IHDR length differs")
    width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(
        ">IIBBBBB", ihdr
    )
    if (
        width != WIDTH
        or height != HEIGHT
        or bit_depth != 4
        or color_type != 3
        or compression != 0
        or filtering != 0
        or interlace != 0
    ):
        raise AuditError("PNG IHDR contract differs")
    palette = chunks[1][1]
    if palette != _palette_bytes():
        raise AuditError("PNG palette differs")

    metadata: dict[str, str] = {}
    for _kind, payload in chunks[2:7]:
        if b"\x00" not in payload:
            raise AuditError("PNG text chunk lacks a separator")
        raw_key, raw_value = payload.split(b"\x00", 1)
        try:
            key = raw_key.decode("latin-1")
            value = raw_value.decode("latin-1")
        except UnicodeDecodeError as error:
            raise AuditError("PNG text metadata is invalid") from error
        if key in metadata:
            raise AuditError("PNG text key is duplicated")
        metadata[key] = value
    if tuple(metadata) != (
        "ClaimBoundary",
        "Description",
        "EvidenceSHA256",
        "TranscriptSHA256",
        "Title",
    ):
        raise AuditError("PNG text metadata order differs")

    row_bytes = WIDTH // 2
    raw = _inflate_stored(chunks[7][1], HEIGHT * (row_bytes + 1))
    pixels = bytearray(WIDTH * HEIGHT)
    source_position = 0
    target_position = 0
    for _row in range(HEIGHT):
        if raw[source_position] != 0:
            raise AuditError("PNG row uses a noncanonical filter")
        source_position += 1
        packed = raw[source_position : source_position + row_bytes]
        source_position += row_bytes
        for packed_value in packed:
            pixels[target_position] = packed_value >> 4
            pixels[target_position + 1] = packed_value & 0x0F
            target_position += 2
    if any(index >= len(PALETTE) for index in pixels):
        raise AuditError("PNG pixel index exceeds the palette")
    return {
        "height": height,
        "metadata": cast(JSONValue, metadata),
        "palette_sha256": _sha256(palette),
        "pixels": bytes(pixels),
        "width": width,
    }


def _read_subblocks(data: bytes, position: int) -> tuple[bytes, int]:
    output = bytearray()
    while True:
        if position >= len(data):
            raise AuditError("GIF sub-block stream is truncated")
        size = data[position]
        position += 1
        if size == 0:
            return bytes(output), position
        if position + size > len(data):
            raise AuditError("GIF sub-block exceeds the file")
        output.extend(data[position : position + size])
        position += size
        if len(output) > MAX_GIF_BLOCK_BYTES:
            raise AuditError("GIF sub-block stream exceeds its byte bound")


def _lzw_decode(payload: bytes, minimum: int, expected_pixels: int) -> bytes:
    if minimum != 4 or not payload:
        raise AuditError("GIF LZW minimum code size differs")
    clear = 1 << minimum
    end = clear + 1
    code_size = minimum + 1
    next_code = end + 1
    table: dict[int, bytes] = {index: bytes((index,)) for index in range(clear)}
    previous: bytes | None = None
    output = bytearray()
    bit_position = 0
    codes = 0
    saw_end = False

    def read_code(width: int) -> int | None:
        nonlocal bit_position
        if bit_position + width > len(payload) * 8:
            return None
        value = 0
        for offset in range(width):
            byte = payload[(bit_position + offset) // 8]
            bit = (byte >> ((bit_position + offset) % 8)) & 1
            value |= bit << offset
        bit_position += width
        return value

    while codes < MAX_GIF_CODES:
        code = read_code(code_size)
        if code is None:
            break
        codes += 1
        if code == clear:
            table = {index: bytes((index,)) for index in range(clear)}
            code_size = minimum + 1
            next_code = end + 1
            previous = None
            continue
        if code == end:
            saw_end = True
            break
        if code in table:
            value = table[code]
        elif code == next_code and previous is not None:
            value = previous + previous[:1]
        else:
            raise AuditError("GIF LZW code is invalid")
        output.extend(value)
        if len(output) > expected_pixels:
            raise AuditError("GIF LZW output exceeds the canvas")
        if previous is not None and next_code < 4096:
            table[next_code] = previous + value[:1]
            next_code += 1
            if next_code == (1 << code_size) and code_size < 12:
                code_size += 1
        previous = value
    if not saw_end or len(output) != expected_pixels:
        raise AuditError("GIF LZW termination or pixel count differs")
    return bytes(output)


def parse_gif(data: bytes) -> dict[str, JSONValue | bytes | list[bytes]]:
    if not data or len(data) > MAX_MEDIA_BYTES or not data.startswith(b"GIF89a"):
        raise AuditError("GIF signature or byte budget differs")
    if len(data) < 13:
        raise AuditError("GIF logical screen is truncated")
    width, height, packed, background, aspect = struct.unpack_from("<HHBBB", data, 6)
    if width != WIDTH or height != HEIGHT or packed != 0xB3 or background != 0 or aspect != 0:
        raise AuditError("GIF logical screen contract differs")
    position = 13
    palette = data[position : position + 48]
    position += 48
    if palette != _palette_bytes():
        raise AuditError("GIF global palette differs")

    global_comments: list[bytes] = []
    frame_comments: list[bytes] = []
    frames: list[bytes] = []
    delays: list[int] = []
    pending_comment: bytes | None = None
    pending_delay: int | None = None
    while position < len(data):
        marker = data[position]
        position += 1
        if marker == 0x3B:
            if position != len(data):
                raise AuditError("GIF has trailing bytes")
            break
        if marker == 0x21:
            if position >= len(data):
                raise AuditError("GIF extension is truncated")
            label = data[position]
            position += 1
            if label == 0xFE:
                comment, position = _read_subblocks(data, position)
                if not frames and pending_delay is None and not frame_comments:
                    if comment == DISCLAIMER.encode("ascii") and not global_comments:
                        global_comments.append(comment)
                    else:
                        pending_comment = comment
                else:
                    pending_comment = comment
                continue
            if label != 0xF9 or position + 6 > len(data):
                raise AuditError("GIF contains an unsupported extension")
            block_size = data[position]
            gce_packed = data[position + 1]
            delay = struct.unpack_from("<H", data, position + 2)[0]
            transparent = data[position + 4]
            terminator = data[position + 5]
            position += 6
            if (
                block_size != 4
                or gce_packed != 0x04
                or transparent != 0
                or terminator != 0
                or pending_delay is not None
            ):
                raise AuditError("GIF graphics control contract differs")
            pending_delay = delay
            continue
        if marker != 0x2C:
            raise AuditError("GIF block marker is unsupported")
        if pending_comment is None or pending_delay is None or position + 9 > len(data):
            raise AuditError("GIF frame metadata is incomplete")
        left, top, frame_width, frame_height, descriptor = struct.unpack_from(
            "<HHHHB", data, position
        )
        position += 9
        if (
            left != 0
            or top != 0
            or frame_width != WIDTH
            or frame_height != HEIGHT
            or descriptor != 0
        ):
            raise AuditError("GIF image descriptor differs")
        if position >= len(data):
            raise AuditError("GIF image data is truncated")
        minimum = data[position]
        position += 1
        compressed, position = _read_subblocks(data, position)
        frames.append(_lzw_decode(compressed, minimum, WIDTH * HEIGHT))
        delays.append(pending_delay)
        frame_comments.append(pending_comment)
        pending_delay = None
        pending_comment = None
        if len(frames) > len(FRAME_STAGES):
            raise AuditError("GIF frame count exceeds its bound")
    else:
        raise AuditError("GIF trailer is missing")

    if (
        global_comments != [DISCLAIMER.encode("ascii")]
        or pending_comment is not None
        or pending_delay is not None
        or len(frames) != len(FRAME_STAGES)
        or tuple(delays) != FRAME_DELAYS_CS
    ):
        raise AuditError("GIF comment, frame, or timing inventory differs")
    return {
        "comments": frame_comments,
        "delays": cast(JSONValue, delays),
        "frames": frames,
        "height": height,
        "palette_sha256": _sha256(palette),
        "width": width,
    }


def verify_bytes(
    media: Mapping[str, bytes],
    sources: Mapping[str, bytes],
) -> dict[str, JSONValue]:
    """Independently audit candidate bytes without importing the renderer."""

    if tuple(sorted(media)) != EXPECTED_MEDIA_FILES:
        raise AuditError("README media inventory is not closed")
    if (
        any(not body or len(body) > MAX_MEDIA_BYTES for body in media.values())
        or sum(map(len, media.values())) > MAX_TOTAL_MEDIA_BYTES
    ):
        raise AuditError("README media exceeds its aggregate byte budget")
    for path, expected_digest in EXPECTED_PRODUCTION_SHA256.items():
        if _sha256(media[path]) != expected_digest:
            raise AuditError(f"production build output differs: {path}")

    validated = _semantic_sources(sources)
    expected_facts = _expected_facts(validated)
    manifest = _parse_json(
        media[MANIFEST_NAME],
        label="README media manifest",
        maximum=MAX_MEDIA_BYTES,
    )
    if set(manifest) != {
        "claim_boundary",
        "disclaimer",
        "freshness_gate",
        "inputs",
        "outputs",
        "schema",
        "tools",
    }:
        raise AuditError("README media manifest field set differs")
    if (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("claim_boundary") != CLAIM_BOUNDARY
        or manifest.get("disclaimer") != DISCLAIMER
        or manifest.get("freshness_gate")
        != "python3 tools/render_readme_visuals.py --check"
    ):
        raise AuditError("README media manifest boundary differs")

    input_records = [
        _object(item, "input record")
        for item in _array(manifest.get("inputs"), "input records")
    ]
    if [record.get("path") for record in input_records] != list(EVIDENCE_PATHS):
        raise AuditError("manifest evidence input inventory differs")
    for record, path in zip(input_records, EVIDENCE_PATHS, strict=True):
        if (
            record.get("bytes") != len(sources[path])
            or record.get("sha256") != _sha256(sources[path])
        ):
            raise AuditError(f"manifest evidence input binding differs: {path}")

    tool_records = [
        _object(item, "tool record")
        for item in _array(manifest.get("tools"), "tool records")
    ]
    if [record.get("path") for record in tool_records] != list(TOOL_PATHS):
        raise AuditError("manifest tool inventory differs")
    for record, path in zip(tool_records, TOOL_PATHS, strict=True):
        if (
            record.get("bytes") != len(sources[path])
            or record.get("sha256") != _sha256(sources[path])
        ):
            raise AuditError(f"manifest tool binding differs: {path}")

    output_records = [
        _object(item, "output record")
        for item in _array(manifest.get("outputs"), "output records")
    ]
    if [record.get("path") for record in output_records] != [GIF_NAME, PNG_NAME]:
        raise AuditError("manifest output order differs")
    output_by_path = {
        _text(record["path"], "output path"): record
        for record in output_records
    }
    for path in (GIF_NAME, PNG_NAME):
        record = output_by_path[path]
        if (
            record.get("bytes") != len(media[path])
            or record.get("sha256") != _sha256(media[path])
            or record.get("width") != WIDTH
            or record.get("height") != HEIGHT
        ):
            raise AuditError(f"manifest output binding differs: {path}")

    png = parse_png(media[PNG_NAME])
    png_record = output_by_path[PNG_NAME]
    png_pixels = cast(bytes, png["pixels"])
    metadata = _object(cast(JSONValue, png["metadata"]), "PNG metadata")
    expected_sources: dict[str, JSONValue] = {
        "evidence": _sha256(sources[EVIDENCE_PATH]),
        "transcript": _sha256(sources[TRANSCRIPT_PATH]),
    }
    if metadata != {
        "ClaimBoundary": "executable-derived-synthetic-fixture",
        "Description": DISCLAIMER,
        "EvidenceSHA256": _sha256(sources[EVIDENCE_PATH]),
        "TranscriptSHA256": _sha256(sources[TRANSCRIPT_PATH]),
        "Title": "KVCrucible verified executable transcript",
    }:
        raise AuditError("PNG evidence metadata differs")
    if (
        png_record.get("media_type") != "image/png"
        or png_record.get("source_sha256") != expected_sources
        or png_record.get("palette_sha256") != png.get("palette_sha256")
        or png_record.get("index_sha256") != _sha256(png_pixels)
        or png_record.get("rgb_sha256") != _sha256(_rgb_bytes(png_pixels))
    ):
        raise AuditError("PNG decoded pixel binding differs")

    gif = parse_gif(media[GIF_NAME])
    gif_record = output_by_path[GIF_NAME]
    gif_frames = cast(list[bytes], gif["frames"])
    gif_comments = cast(list[bytes], gif["comments"])
    frame_records = [
        _object(item, "frame record")
        for item in _array(gif_record.get("frames"), "frame records")
    ]
    if (
        gif_record.get("media_type") != "image/gif"
        or gif_record.get("frame_count") != len(FRAME_STAGES)
        or gif_record.get("playback") != "once"
        or gif_record.get("palette_sha256") != gif.get("palette_sha256")
        or len(frame_records) != len(FRAME_STAGES)
    ):
        raise AuditError("GIF manifest contract differs")

    for index, (stage, delay, facts, frame, comment, record) in enumerate(
        zip(
            FRAME_STAGES,
            FRAME_DELAYS_CS,
            expected_facts,
            gif_frames,
            gif_comments,
            frame_records,
            strict=True,
        )
    ):
        encoded_facts = _canonical(cast(JSONValue, facts))
        if comment != FRAME_COMMENT_PREFIX + encoded_facts:
            raise AuditError(f"GIF frame {index} evidence comment differs")
        if (
            record.get("stage") != stage
            or record.get("delay_cs") != delay
            or record.get("facts") != facts
            or record.get("facts_sha256") != _sha256(encoded_facts)
            or record.get("index_sha256") != _sha256(frame)
            or record.get("rgb_sha256") != _sha256(_rgb_bytes(frame))
        ):
            raise AuditError(f"GIF frame {index} manifest binding differs")

    return {
        "frame_count": len(gif_frames),
        "gif_sha256": _sha256(media[GIF_NAME]),
        "height": HEIGHT,
        "manifest_sha256": _sha256(media[MANIFEST_NAME]),
        "png_sha256": _sha256(media[PNG_NAME]),
        "source_sha256": expected_sources,
        "status": "ok",
        "width": WIDTH,
    }


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


def _read_relative(root: Path, relative: str, maximum: int) -> bytes:
    parts = Path(relative).parts
    if (
        not parts
        or Path(relative).is_absolute()
        or ".." in parts
        or Path(relative).as_posix() != relative
    ):
        raise AuditError(f"unsafe path: {relative}")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    current = root_fd
    opened: list[int] = []
    try:
        for part in parts[:-1]:
            descriptor = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            opened.append(descriptor)
            current = descriptor
        descriptor = os.open(
            parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=current,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
                or metadata.st_size > maximum
            ):
                raise AuditError(f"file contract differs: {relative}")
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    raise AuditError(f"file was truncated: {relative}")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1) or _stable_stat(os.fstat(descriptor)) != _stable_stat(
                metadata
            ):
                raise AuditError(f"file changed while being read: {relative}")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)
        os.close(root_fd)


def load_sources(repository: Path) -> dict[str, bytes]:
    root = repository.resolve(strict=True)
    return {path: _read_relative(root, path, MAX_SOURCE_BYTES) for path in SOURCE_PATHS}


def load_media(directory: Path) -> dict[str, bytes]:
    if directory.is_symlink():
        raise AuditError("candidate media directory cannot be a symbolic link")
    try:
        root = directory.resolve(strict=True)
        if not root.is_dir():
            raise AuditError("candidate media path is not a directory")
        entries = tuple(sorted(entry.name for entry in os.scandir(root)))
        if entries != EXPECTED_MEDIA_FILES:
            raise AuditError("candidate media directory inventory is not closed")
        return {name: _read_relative(root, name, MAX_MEDIA_BYTES) for name in EXPECTED_MEDIA_FILES}
    except OSError as error:
        raise AuditError("candidate media directory cannot be read safely") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Independently audit deterministic KVCrucible README media"
    )
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        report = verify_bytes(
            load_media(cast(Path, arguments.directory)),
            load_sources(cast(Path, arguments.repository)),
        )
        print(_canonical(cast(JSONValue, report)).decode("ascii"))
        return 0
    except (AuditError, OSError, UnicodeError) as error:
        message = " ".join(str(error).split())[:512]
        print(f"README media audit error: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
