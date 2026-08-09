from __future__ import annotations

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


class ReadmeMediaRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.renderer = load_module(
            "tools/render_readme_media.py",
            "kvcrucible_readme_media_renderer_test",
        )
        cls.sources = cls.renderer.load_sources(ROOT)
        cls.outputs = cls.renderer.render_media(cls.sources)

    def test_source_inventory_separates_evidence_from_tools(self) -> None:
        self.assertEqual(
            self.renderer.EVIDENCE_PATHS,
            (
                "docs/visuals/generated/terminal-transcript.txt",
                "docs/visuals/generated/visual-evidence.json",
            ),
        )
        self.assertEqual(
            self.renderer.TOOL_PATHS,
            (
                "scripts/verify_readme_media.py",
                "tools/render_readme_media.py",
            ),
        )
        self.assertEqual(tuple(sorted(self.sources)), self.renderer.SOURCE_PATHS)

    def test_closed_output_inventory_and_byte_budgets(self) -> None:
        self.assertEqual(
            tuple(sorted(self.outputs)),
            (
                "manifest.sha256.json",
                "terminal-transcript.png",
                "verdict-fault-workflow.gif",
            ),
        )
        self.assertTrue(all(self.outputs.values()))
        self.assertLessEqual(
            sum(map(len, self.outputs.values())),
            self.renderer.MAX_TOTAL_OUTPUT_BYTES,
        )

    def test_render_is_byte_deterministic(self) -> None:
        self.assertEqual(
            self.renderer.render_media(self.sources),
            self.outputs,
        )

    def test_manifest_records_reviewed_frame_sequence(self) -> None:
        manifest = json.loads(self.outputs["manifest.sha256.json"])
        self.assertEqual(
            manifest["schema"],
            "kvcrucible.readme-media-manifest/v1",
        )
        self.assertEqual(
            manifest["disclaimer"],
            (
                "EVIDENCE-DERIVED | SYNTHETIC OFFLINE FIXTURE | "
                "NOT OS CAPTURE | NOT BENCHMARK"
            ),
        )
        gif = manifest["outputs"][0]
        self.assertEqual(gif["playback"], "once")
        self.assertEqual(
            [frame["stage"] for frame in gif["frames"]],
            list(self.renderer.FRAME_STAGES),
        )
        self.assertEqual(
            [frame["delay_cs"] for frame in gif["frames"]],
            list(self.renderer.FRAME_DELAYS_CS),
        )

    def test_png_is_an_evidence_plate_not_an_os_capture(self) -> None:
        png = self.outputs["terminal-transcript.png"]
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn(b"NOT OS CAPTURE", png)
        self.assertIn(b"NOT BENCHMARK", png)
        self.assertNotIn(b"Screenshot", png)

    def test_gif_is_once_only_and_has_no_loop_extension(self) -> None:
        gif = self.outputs["verdict-fault-workflow.gif"]
        self.assertTrue(gif.startswith(b"GIF89a"))
        self.assertNotIn(b"NETSCAPE", gif)
        self.assertNotIn(b"ANIMEXTS", gif)

    def test_fault_transcript_tamper_fails_closed(self) -> None:
        sources = dict(self.sources)
        sources[self.renderer.TRANSCRIPT_PATH] = sources[
            self.renderer.TRANSCRIPT_PATH
        ].replace(b"e2#0 Buffered", b"e2#0 Applied", 1)
        with self.assertRaisesRegex(
            self.renderer.MediaError,
            "fault transcript",
        ):
            self.renderer.render_media(sources)

    def test_duplicate_evidence_key_fails_closed(self) -> None:
        sources = dict(self.sources)
        body = sources[self.renderer.EVIDENCE_PATH]
        sources[self.renderer.EVIDENCE_PATH] = body.replace(
            b'{\n  "captures":',
            b'{\n  "captures": {},\n  "captures":',
            1,
        )
        with self.assertRaisesRegex(
            self.renderer.MediaError,
            "duplicate JSON key",
        ):
            self.renderer.render_media(sources)

    def test_committed_media_reader_uses_output_byte_budget(self) -> None:
        committed = self.renderer._read_media_directory(
            ROOT / "docs/visuals/media"
        )
        self.assertGreater(
            len(committed["terminal-transcript.png"]),
            self.renderer.MAX_SOURCE_BYTES,
        )
        self.assertEqual(committed, self.outputs)

    def test_tool_bytes_are_bound_but_not_semantic_authority(self) -> None:
        changed = dict(self.sources)
        changed[self.renderer.AUDITOR_PATH] += b"\n"
        outputs = self.renderer.render_media(changed)
        self.assertEqual(
            outputs["terminal-transcript.png"],
            self.outputs["terminal-transcript.png"],
        )
        self.assertEqual(
            outputs["verdict-fault-workflow.gif"],
            self.outputs["verdict-fault-workflow.gif"],
        )
        self.assertNotEqual(
            outputs["manifest.sha256.json"],
            self.outputs["manifest.sha256.json"],
        )


if __name__ == "__main__":
    unittest.main()
