from __future__ import annotations

import ast
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReadmeMediaVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.renderer = load_module(
            "tools/render_readme_media.py",
            "kvcrucible_media_renderer_for_audit_test",
        )
        cls.verifier = load_module(
            "scripts/verify_readme_media.py",
            "kvcrucible_independent_media_auditor_test",
        )
        cls.sources = cls.renderer.load_sources(ROOT)
        cls.media = cls.renderer.render_media(cls.sources)

    def test_verifier_does_not_import_renderer(self) -> None:
        source = (ROOT / "scripts/verify_readme_media.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        imported.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertFalse(
            any(name and "render_readme_media" in name for name in imported)
        )

    def test_exact_candidate_passes_independent_audit(self) -> None:
        report = self.verifier.verify_bytes(self.media, self.sources)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["frame_count"], 6)
        self.assertEqual((report["width"], report["height"]), (1440, 820))

    def test_png_crc_tamper_is_rejected(self) -> None:
        png = bytearray(self.media["terminal-transcript.png"])
        png[-5] ^= 1
        with self.assertRaisesRegex(self.verifier.AuditError, "CRC"):
            self.verifier.parse_png(bytes(png))

    def test_png_metadata_binds_both_evidence_sources(self) -> None:
        parsed = self.verifier.parse_png(
            self.media["terminal-transcript.png"]
        )
        metadata = parsed["metadata"]
        self.assertEqual(
            metadata["TranscriptSHA256"],
            self.verifier._sha256(
                self.sources[self.verifier.TRANSCRIPT_PATH]
            ),
        )
        self.assertEqual(
            metadata["EvidenceSHA256"],
            self.verifier._sha256(
                self.sources[self.verifier.EVIDENCE_PATH]
            ),
        )

    def test_gif_application_extension_is_rejected(self) -> None:
        gif = self.media["verdict-fault-workflow.gif"]
        injected = gif[:61] + b"\x21\xff\x00" + gif[61:]
        with self.assertRaisesRegex(
            self.verifier.AuditError,
            "unsupported extension",
        ):
            self.verifier.parse_gif(injected)

    def test_gif_frame_facts_are_reconstructed_independently(self) -> None:
        parsed = self.verifier.parse_gif(
            self.media["verdict-fault-workflow.gif"]
        )
        self.assertEqual(parsed["delays"], list(self.verifier.FRAME_DELAYS_CS))
        self.assertEqual(len(parsed["frames"]), len(self.verifier.FRAME_STAGES))
        self.assertEqual(
            len(parsed["comments"]),
            len(self.verifier.FRAME_STAGES),
        )

    def test_manifest_claim_boundary_tamper_is_rejected(self) -> None:
        media = dict(self.media)
        manifest = json.loads(media["manifest.sha256.json"])
        manifest["claim_boundary"]["benchmark"] = True
        media["manifest.sha256.json"] = (
            json.dumps(
                manifest,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
            + b"\n"
        )
        with self.assertRaisesRegex(
            self.verifier.AuditError,
            "manifest boundary",
        ):
            self.verifier.verify_bytes(media, self.sources)

    def test_source_tamper_is_rejected_before_media_trust(self) -> None:
        sources = dict(self.sources)
        sources[self.verifier.TRANSCRIPT_PATH] = sources[
            self.verifier.TRANSCRIPT_PATH
        ].replace(b"e1#1 Duplicate", b"e1#1 Applied  ", 1)
        with self.assertRaises(self.verifier.AuditError):
            self.verifier.verify_bytes(self.media, sources)

    def test_media_inventory_is_closed(self) -> None:
        media = dict(self.media)
        media["unexpected.txt"] = b"x"
        with self.assertRaisesRegex(
            self.verifier.AuditError,
            "inventory",
        ):
            self.verifier.verify_bytes(media, self.sources)


if __name__ == "__main__":
    unittest.main()
