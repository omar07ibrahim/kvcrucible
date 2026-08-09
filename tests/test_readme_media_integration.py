from __future__ import annotations

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MEDIA = ROOT / "docs" / "visuals" / "media"


def load_verifier():
    path = ROOT / "scripts" / "verify_readme_media.py"
    spec = importlib.util.spec_from_file_location(
        "kvcrucible_published_media_verifier_test",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load README media verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublishedReadmeMediaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.verifier = load_verifier()

    def test_media_directory_inventory_is_closed(self) -> None:
        self.assertTrue(MEDIA.is_dir())
        self.assertFalse(MEDIA.is_symlink())
        self.assertEqual(
            tuple(sorted(path.name for path in MEDIA.iterdir())),
            (
                "manifest.sha256.json",
                "terminal-transcript.png",
                "verdict-fault-workflow.gif",
            ),
        )
        self.assertTrue(all(path.is_file() for path in MEDIA.iterdir()))
        self.assertTrue(all(not path.is_symlink() for path in MEDIA.iterdir()))

    def test_reviewed_raster_hashes_are_pinned(self) -> None:
        expected = {
            "terminal-transcript.png": (
                "b0ecd9ee01a2c9e128313350290aacaa"
                "9856988d47ba6a57eaef880d3ae1a509"
            ),
            "verdict-fault-workflow.gif": (
                "380257ca603264444db66947fa8b2eff"
                "829f85a6e735395c10cf5353ad19ef2a"
            ),
        }
        self.assertEqual(self.verifier.EXPECTED_PRODUCTION_SHA256, {
            self.verifier.PNG_NAME: expected["terminal-transcript.png"],
            self.verifier.GIF_NAME: expected["verdict-fault-workflow.gif"],
        })
        for name, digest in expected.items():
            self.assertEqual(
                hashlib.sha256((MEDIA / name).read_bytes()).hexdigest(),
                digest,
            )

    def test_manifest_declares_once_only_honest_boundary(self) -> None:
        manifest = json.loads(
            (MEDIA / "manifest.sha256.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            manifest["disclaimer"],
            (
                "EVIDENCE-DERIVED | SYNTHETIC OFFLINE FIXTURE | "
                "NOT OS CAPTURE | NOT BENCHMARK"
            ),
        )
        self.assertFalse(manifest["claim_boundary"]["os_capture"])
        self.assertFalse(manifest["claim_boundary"]["benchmark"])
        self.assertEqual(manifest["outputs"][0]["playback"], "once")
        self.assertEqual(manifest["outputs"][0]["frame_count"], 6)

    def test_readme_embeds_media_with_static_alternatives(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(
            readme.count("docs/visuals/media/terminal-transcript.png"),
            2,
        )
        self.assertEqual(
            readme.count("docs/visuals/media/verdict-fault-workflow.gif"),
            2,
        )
        self.assertIn(
            "docs/visuals/generated/fault-timeline.svg",
            readme,
        )
        self.assertIn(
            "docs/visuals/generated/verdict-matrix.svg",
            readme,
        )
        lowered = readme.lower()
        self.assertIn("not an os screenshot or terminal capture", lowered)
        self.assertIn("makes no benchmark claim", lowered)
        self.assertIn("animation plays once", lowered)

    def test_permanent_workflow_audits_committed_bytes_by_id(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "readme-media.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("pull_request:", workflow)
        self.assertIn("push:", workflow)
        self.assertIn("Require exact committed media", workflow)
        self.assertIn("artifact-ids:", workflow)
        self.assertIn("compression-level: 0", workflow)
        self.assertIn("cancel-in-progress: false", workflow)


if __name__ == "__main__":
    unittest.main()
