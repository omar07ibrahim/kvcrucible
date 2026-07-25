"""Security and determinism tests for the README evidence renderer."""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import selectors
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
RENDERER_PATH = REPOSITORY_ROOT / "tools" / "render_readme_visuals.py"

SPEC = importlib.util.spec_from_file_location(
    "kvcrucible_render_readme_visuals",
    RENDERER_PATH,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the README evidence renderer")
RENDERER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RENDERER
SPEC.loader.exec_module(RENDERER)


def reviewed_verdicts() -> list[dict[str, object]]:
    evidence_path = (
        REPOSITORY_ROOT / "docs" / "visuals" / "generated" / "visual-evidence.json"
    )
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    return evidence["verdicts"]


def process_state(process_id: int) -> str | None:
    try:
        fields = Path(f"/proc/{process_id}/stat").read_text().split()
    except FileNotFoundError:
        return None
    return fields[2]


def assert_process_disappears(
    test: unittest.TestCase,
    process_id: int,
    *,
    timeout_seconds: float = 2,
) -> None:
    if not sys.platform.startswith("linux") or not Path(
        "/proc/self/stat"
    ).is_file():
        raise unittest.SkipTest(
            "process disappearance assertion requires Linux /proc"
        )
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process_state(process_id) is None:
            return
        os.sched_yield()
    test.fail(
        f"process {process_id} survived cleanup in state "
        f"{process_state(process_id)!r}"
    )


class ContractValidationTests(unittest.TestCase):
    def test_reviewed_contract_is_accepted_exactly(self) -> None:
        RENDERER.validate_contract(copy.deepcopy(RENDERER.EXPECTED_CONTRACT))

    def test_status_tampering_is_rejected(self) -> None:
        contract = copy.deepcopy(RENDERER.EXPECTED_CONTRACT)
        contract["status"] = "everything implemented"

        with self.assertRaisesRegex(
            RENDERER.EvidenceError,
            "contract field 'status' does not match the reviewed evidence contract",
        ):
            RENDERER.validate_contract(contract)

    def test_capability_promotion_is_rejected_before_rendering(self) -> None:
        contract = copy.deepcopy(RENDERER.EXPECTED_CONTRACT)
        promoted = contract["planned_v0_1_capabilities"].pop(0)
        contract["implemented_capabilities"].append(promoted)
        captures = {
            "contract": RENDERER.Capture(
                "fake contract",
                json.dumps(contract),
            ),
            "verdicts": RENDERER.Capture("fake verdicts", "[]"),
        }

        with self.assertRaisesRegex(
            RENDERER.EvidenceError,
            "contract field 'implemented_capabilities' does not match "
            "the reviewed evidence contract",
        ):
            RENDERER.build_outputs(captures)

    def test_verdict_schedule_tampering_is_rejected(self) -> None:
        verdicts = reviewed_verdicts()
        verdicts[0]["schedule"] = "drop-middle"

        with self.assertRaisesRegex(
            RENDERER.EvidenceError,
            "unexpected schedule for synthetic/reorder-and-duplicate",
        ):
            RENDERER.validate_verdicts(verdicts)

    def test_verdict_top_level_extra_field_is_rejected(self) -> None:
        verdicts = reviewed_verdicts()
        verdicts[1]["unreviewed"] = True

        with self.assertRaisesRegex(
            RENDERER.EvidenceError,
            "verdict row .* has an unexpected field set",
        ):
            RENDERER.validate_verdicts(verdicts)

    def test_verdict_nested_extra_field_is_rejected(self) -> None:
        verdicts = reviewed_verdicts()
        pristine = verdicts[2]["pristine"]
        assert isinstance(pristine, dict)
        pristine["unreviewed"] = True

        with self.assertRaisesRegex(
            RENDERER.EvidenceError,
            "pristine evidence has an unexpected field set",
        ):
            RENDERER.validate_verdicts(verdicts)


class ProcessBoundaryTests(unittest.TestCase):
    def test_generator_exit_and_cleanup_failure_preserve_both(self) -> None:
        collection_error = GeneratorExit("injected collection exit")
        cleanup_error = RuntimeError("injected cleanup failure")

        with self.assertRaises(BaseExceptionGroup) as caught:
            RENDERER.raise_collection_cleanup_failure(
                "injected command",
                collection_error,
                cleanup_error,
            )

        self.assertEqual(
            caught.exception.exceptions,
            (collection_error, cleanup_error),
        )

    def test_cleanup_control_flow_and_ordinary_failure_preserve_both(
        self,
    ) -> None:
        for cleanup_error in (
            KeyboardInterrupt(),
            SystemExit(17),
        ):
            with self.subTest(cleanup_error=type(cleanup_error).__name__):
                collection_error = RuntimeError(
                    "injected collection failure"
                )

                with self.assertRaises(BaseExceptionGroup) as caught:
                    RENDERER.raise_collection_cleanup_failure(
                        "injected command",
                        collection_error,
                        cleanup_error,
                    )

                self.assertEqual(
                    caught.exception.exceptions,
                    (collection_error, cleanup_error),
                )

    def test_ordinary_dual_failure_is_chained_from_exception_group(
        self,
    ) -> None:
        collection_error = OSError("injected collection failure")
        cleanup_error = RuntimeError("injected cleanup failure")

        with self.assertRaises(RENDERER.EvidenceError) as caught:
            RENDERER.raise_collection_cleanup_failure(
                "injected command",
                collection_error,
                cleanup_error,
            )

        cause = caught.exception.__cause__
        self.assertIsInstance(cause, ExceptionGroup)
        assert isinstance(cause, ExceptionGroup)
        self.assertEqual(
            cause.exceptions,
            (collection_error, cleanup_error),
        )

    def test_environment_uses_only_reviewed_passthrough_keys(self) -> None:
        source = {
            "PATH": "/bin",
            "CARGO_HOME": "/cargo",
            "RUSTUP_HOME": "/rustup",
            "AWS_SECRET_ACCESS_KEY": "must-not-cross",
            "GITHUB_TOKEN": "must-not-cross",
            "RANDOM_SETTING": "must-not-cross",
        }
        with mock.patch.dict(os.environ, source, clear=True):
            actual = RENDERER.capture_environment()

        expected = {
            "PATH": "/bin",
            "CARGO_HOME": "/cargo",
            "RUSTUP_HOME": "/rustup",
            **RENDERER.FIXED_ENVIRONMENT,
        }
        self.assertEqual(actual, expected)

    def test_subprocess_does_not_receive_unlisted_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"KVC_RENDERER_UNLISTED": "must-not-cross"},
            clear=False,
        ):
            capture = RENDERER.run(
                (
                    sys.executable,
                    "-c",
                    (
                        "import os; "
                        "print(os.environ.get('KVC_RENDERER_UNLISTED', 'absent'))"
                    ),
                ),
                timeout_seconds=2,
            )

        self.assertEqual(capture.stdout, "absent\n")

    def test_subprocess_timeout_is_bounded_and_stable(self) -> None:
        with self.assertRaisesRegex(
            RENDERER.EvidenceError,
            "exceeded 0.05 seconds",
        ):
            RENDERER.run(
                (
                    sys.executable,
                    "-c",
                    "import time; time.sleep(5)",
                ),
                timeout_seconds=0.05,
            )

    def test_subprocess_output_is_bounded(self) -> None:
        with self.assertRaisesRegex(
            RENDERER.EvidenceError,
            "exceeded the 64-byte stdout limit",
        ):
            RENDERER.run(
                (
                    sys.executable,
                    "-c",
                    "import os; os.write(1, b'x' * 65)",
                ),
                timeout_seconds=2,
                output_limit_bytes=64,
            )

    def test_subprocess_stderr_is_bounded(self) -> None:
        with self.assertRaisesRegex(
            RENDERER.EvidenceError,
            "exceeded the 64-byte stderr limit",
        ):
            RENDERER.run(
                (
                    sys.executable,
                    "-c",
                    "import os; os.write(2, b'e' * 65)",
                ),
                timeout_seconds=2,
                output_limit_bytes=64,
            )

    def test_subprocess_dual_pipe_output_at_limit_is_accepted(self) -> None:
        capture = RENDERER.run(
            (
                sys.executable,
                "-c",
                "import os; os.write(1, b'o' * 64); os.write(2, b'e' * 64)",
            ),
            timeout_seconds=2,
            output_limit_bytes=64,
        )

        self.assertEqual(capture.stdout, "o" * 64)

    def test_injected_collection_failure_kills_and_reaps_child(self) -> None:
        observed_process_ids: list[int] = []

        def fail_collection(
            process: object,
            _command_text: str,
            *,
            timeout_seconds: float,
            output_limit_bytes: int,
        ) -> tuple[bytes, bytes]:
            del timeout_seconds, output_limit_bytes
            observed_process_ids.append(process.pid)
            raise OSError("injected collection failure")

        with mock.patch.object(
            RENDERER,
            "collect_process_output",
            side_effect=fail_collection,
        ):
            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "output collection failed: OSError",
            ):
                RENDERER.run(
                    (
                        sys.executable,
                        "-c",
                        "import signal; signal.pause()",
                    ),
                    timeout_seconds=2,
                )

        self.assertEqual(len(observed_process_ids), 1)
        assert_process_disappears(self, observed_process_ids[0])

    def test_keyboard_interrupt_is_preserved_after_process_cleanup(self) -> None:
        observed_process_ids: list[int] = []

        def interrupt_collection(
            process: object,
            _command_text: str,
            *,
            timeout_seconds: float,
            output_limit_bytes: int,
        ) -> tuple[bytes, bytes]:
            del timeout_seconds, output_limit_bytes
            observed_process_ids.append(process.pid)
            raise KeyboardInterrupt

        with mock.patch.object(
            RENDERER,
            "collect_process_output",
            side_effect=interrupt_collection,
        ):
            with self.assertRaises(KeyboardInterrupt):
                RENDERER.run(
                    (
                        sys.executable,
                        "-c",
                        "import signal; signal.pause()",
                    ),
                    timeout_seconds=2,
                )

        self.assertEqual(len(observed_process_ids), 1)
        assert_process_disappears(self, observed_process_ids[0])

    def test_collection_failure_cleans_child_and_grandchild_group(self) -> None:
        observed_process_ids: list[int] = []
        child_program = (
            "import signal,sys;"
            "signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));"
            "signal.pause()"
        )
        leader_program = "\n".join(
            (
                "import signal,subprocess,sys",
                (
                    "child=subprocess.Popen("
                    "[sys.executable,'-c',sys.argv[1]])"
                ),
                "def stop(*_):",
                "    child.terminate()",
                "    child.wait(timeout=1)",
                "    raise SystemExit(0)",
                "signal.signal(signal.SIGTERM,stop)",
                "print(f'{__import__(\"os\").getpid()} {child.pid}',flush=True)",
                "signal.pause()",
            )
        )

        def fail_after_sentinel(
            process: object,
            _command_text: str,
            *,
            timeout_seconds: float,
            output_limit_bytes: int,
        ) -> tuple[bytes, bytes]:
            del output_limit_bytes
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                events = selector.select(timeout_seconds)
                if not events:
                    self.fail("child/grandchild sentinel was not emitted")
                line = process.stdout.readline()
            finally:
                selector.close()
            observed_process_ids.extend(int(value) for value in line.split())
            raise OSError("injected post-sentinel collection failure")

        with mock.patch.object(
            RENDERER,
            "collect_process_output",
            side_effect=fail_after_sentinel,
        ):
            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "output collection failed: OSError",
            ):
                RENDERER.run(
                    (
                        sys.executable,
                        "-c",
                        leader_program,
                        child_program,
                    ),
                    timeout_seconds=2,
                )

        self.assertEqual(len(observed_process_ids), 2)
        for process_id in observed_process_ids:
            assert_process_disappears(self, process_id)


class FileBoundaryTests(unittest.TestCase):
    def temporary_directory(self) -> tempfile.TemporaryDirectory[str]:
        target = RENDERER.ROOT / "target"
        target.mkdir(exist_ok=True)
        return tempfile.TemporaryDirectory(
            prefix=".renderer-test-",
            dir=target,
        )

    def test_bounded_read_rejects_oversized_input(self) -> None:
        with self.temporary_directory() as directory_name:
            path = Path(directory_name) / "source.txt"
            path.write_bytes(b"12345")

            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "exceeds the 4-byte read limit",
            ):
                RENDERER.read_bounded_regular_file(
                    path,
                    limit_bytes=4,
                    label="test input",
                )

    def test_descriptor_advance_closes_new_fd_if_previous_close_fails(
        self,
    ) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            old_descriptor = os.open(
                directory,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            new_descriptor = os.open(
                directory,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            real_close = os.close
            primary_error = OSError("injected previous close failure")

            def fail_previous_close(descriptor: int) -> None:
                if descriptor == old_descriptor:
                    raise primary_error
                real_close(descriptor)

            try:
                with mock.patch.object(
                    RENDERER.os,
                    "close",
                    side_effect=fail_previous_close,
                ):
                    with self.assertRaises(OSError) as caught:
                        RENDERER.advance_directory_descriptor(
                            old_descriptor,
                            new_descriptor,
                        )

                self.assertIs(caught.exception, primary_error)
                with self.assertRaises(OSError):
                    os.fstat(new_descriptor)
            finally:
                try:
                    real_close(old_descriptor)
                except OSError:
                    pass

    def test_input_symlink_is_rejected(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            source = directory / "source.txt"
            source.write_bytes(b"reviewed")
            link = directory / "linked.txt"
            link.symlink_to(source.name)

            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "test input must not be a symlink",
            ):
                RENDERER.read_bounded_regular_file(
                    link,
                    limit_bytes=64,
                    label="test input",
                )

    def test_input_parent_symlink_is_rejected(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            real_parent = directory / "real"
            real_parent.mkdir()
            (real_parent / "source.txt").write_bytes(b"reviewed")
            linked_parent = directory / "linked"
            linked_parent.symlink_to(real_parent.name, target_is_directory=True)

            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "test input parent must not be a symlink",
            ):
                RENDERER.read_bounded_regular_file(
                    linked_parent / "source.txt",
                    limit_bytes=64,
                    label="test input",
                )

    def test_non_regular_input_is_rejected(self) -> None:
        with self.temporary_directory() as directory_name:
            path = Path(directory_name) / "source"
            path.mkdir()

            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "test input must be a regular file",
            ):
                RENDERER.read_bounded_regular_file(
                    path,
                    limit_bytes=64,
                    label="test input",
                )

    def test_manifest_walk_rejects_a_symlink_directory(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            real_directory = directory / "real"
            real_directory.mkdir()
            (real_directory / "source.rs").write_bytes(b"reviewed")
            (directory / "linked").symlink_to(
                real_directory.name,
                target_is_directory=True,
            )
            directory_fd = RENDERER.open_repository_directory(
                directory,
                "test manifest directory",
            )
            try:
                with self.assertRaisesRegex(
                    RENDERER.EvidenceError,
                    "manifest discovery entry must not be a symlink",
                ):
                    RENDERER.walk_manifest_sources_at(
                        directory_fd,
                        "src",
                        recursive=True,
                        paths=set(),
                        visited_entries=[0],
                        depth=0,
                    )
            finally:
                os.close(directory_fd)

    def test_manifest_walk_rejects_parent_swap_before_child_open(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            walk_root = directory / "walk"
            walk_root.mkdir()
            trusted = walk_root / "nested"
            trusted.mkdir()
            (trusted / "trusted.rs").write_bytes(b"trusted")
            outside = directory / "outside"
            outside.mkdir()
            (outside / "redirected.rs").write_bytes(b"redirected")
            displaced = walk_root / "displaced"
            real_open_directory_at = RENDERER.open_directory_at
            swapped = False

            def swap_before_open(
                directory_fd: int,
                name: str,
                label: str,
                display: str,
            ) -> int:
                nonlocal swapped
                if name == "nested" and label == "manifest discovery directory":
                    trusted.rename(displaced)
                    trusted.symlink_to("../outside", target_is_directory=True)
                    swapped = True
                return real_open_directory_at(
                    directory_fd,
                    name,
                    label,
                    display,
                )

            directory_fd = RENDERER.open_repository_directory(
                walk_root,
                "test manifest directory",
            )
            paths: set[str] = set()
            try:
                with mock.patch.object(
                    RENDERER,
                    "open_directory_at",
                    side_effect=swap_before_open,
                ):
                    with self.assertRaisesRegex(
                        RENDERER.EvidenceError,
                        "manifest discovery directory must not be a symlink",
                    ):
                        RENDERER.walk_manifest_sources_at(
                            directory_fd,
                            "src",
                            recursive=True,
                            paths=paths,
                            visited_entries=[0],
                            depth=0,
                        )
            finally:
                os.close(directory_fd)

            self.assertTrue(swapped)
            self.assertNotIn("src/nested/redirected.rs", paths)
            trusted.unlink()
            displaced.rename(trusted)

    def test_manifest_walk_counts_ignored_directories(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            for index in range(3):
                (directory / f"empty-{index}").mkdir()
            directory_fd = RENDERER.open_repository_directory(
                directory,
                "test manifest directory",
            )
            try:
                with mock.patch.object(
                    RENDERER,
                    "MAX_MANIFEST_DISCOVERY_ENTRIES",
                    2,
                ):
                    with self.assertRaisesRegex(
                        RENDERER.EvidenceError,
                        "manifest discovery entry count exceeds",
                    ):
                        RENDERER.walk_manifest_sources_at(
                            directory_fd,
                            "src",
                            recursive=True,
                            paths=set(),
                            visited_entries=[0],
                            depth=0,
                        )
            finally:
                os.close(directory_fd)

    def test_output_symlink_is_rejected_without_touching_its_target(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            victim = directory / "victim.txt"
            victim.write_bytes(b"unchanged")
            output = directory / "artifact.txt"
            output.symlink_to(victim.name)

            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "generated output must not be a symlink",
            ):
                RENDERER.write_outputs(
                    {"artifact.txt": b"replacement"},
                    output_directory=directory,
                    expected_outputs=("artifact.txt",),
                )

            self.assertEqual(victim.read_bytes(), b"unchanged")

    def test_output_directory_symlink_is_rejected(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            real_output = directory / "real-output"
            real_output.mkdir()
            linked_output = directory / "linked-output"
            linked_output.symlink_to(real_output.name, target_is_directory=True)

            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "visual evidence directory must not be a symlink",
            ):
                RENDERER.write_outputs(
                    {"artifact.txt": b"replacement"},
                    output_directory=linked_output,
                    expected_outputs=("artifact.txt",),
                )

            self.assertEqual(list(real_output.iterdir()), [])

    def test_output_parent_symlink_is_rejected(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            real_parent = directory / "real-parent"
            real_parent.mkdir()
            real_output = real_parent / "generated"
            real_output.mkdir()
            linked_parent = directory / "linked-parent"
            linked_parent.symlink_to(real_parent.name, target_is_directory=True)

            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "visual evidence directory parent must not be a symlink",
            ):
                RENDERER.write_outputs(
                    {"artifact.txt": b"replacement"},
                    output_directory=linked_parent / "generated",
                    expected_outputs=("artifact.txt",),
                )

            self.assertEqual(list(real_output.iterdir()), [])

    def test_non_regular_output_is_rejected(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            (directory / "artifact.txt").mkdir()

            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "generated output must be a regular file",
            ):
                RENDERER.write_outputs(
                    {"artifact.txt": b"replacement"},
                    output_directory=directory,
                    expected_outputs=("artifact.txt",),
                )

    def test_atomic_write_replaces_complete_file_and_cleans_staging(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            target = directory / "artifact.txt"
            target.write_bytes(b"before")
            replacements: list[tuple[str, str, int, int]] = []
            real_replace = os.replace

            def record_replace(
                source: str,
                destination: str,
                *,
                src_dir_fd: int,
                dst_dir_fd: int,
            ) -> None:
                replacements.append(
                    (source, destination, src_dir_fd, dst_dir_fd)
                )
                real_replace(
                    source,
                    destination,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            with mock.patch.object(
                RENDERER.os,
                "replace",
                side_effect=record_replace,
            ):
                RENDERER.atomic_write(target, b"after")

            self.assertEqual(target.read_bytes(), b"after")
            self.assertEqual(len(replacements), 1)
            source, destination, source_fd, destination_fd = replacements[0]
            self.assertNotIn("/", source)
            self.assertEqual(destination, target.name)
            self.assertEqual(source_fd, destination_fd)
            self.assertEqual(
                [path.name for path in directory.iterdir()],
                ["artifact.txt"],
            )

    def test_atomic_write_failure_preserves_target_and_cleans_staging(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            target = directory / "artifact.txt"
            target.write_bytes(b"before")

            with mock.patch.object(
                RENDERER.os,
                "replace",
                side_effect=OSError("injected replace failure"),
            ):
                with self.assertRaisesRegex(
                    RENDERER.EvidenceError,
                    "could not atomically write .*injected replace failure",
                ):
                    RENDERER.atomic_write(target, b"after")

            self.assertEqual(target.read_bytes(), b"before")
            self.assertEqual(
                [path.name for path in directory.iterdir()],
                ["artifact.txt"],
            )

    def test_atomic_cleanup_failure_is_attached_to_primary_error(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            target = directory / "artifact.txt"
            target.write_bytes(b"before")

            directory_fd = RENDERER.open_repository_directory(
                directory,
                "visual evidence directory",
            )
            try:
                with (
                    mock.patch.object(
                        RENDERER.os,
                        "replace",
                        side_effect=OSError("injected replace failure"),
                    ),
                    mock.patch.object(
                        RENDERER.os,
                        "unlink",
                        side_effect=OSError("injected unlink failure"),
                    ),
                ):
                    with self.assertRaises(RENDERER.EvidenceError) as caught:
                        RENDERER.atomic_write_at(
                            directory_fd,
                            target.name,
                            b"after",
                            display="artifact.txt",
                        )
            finally:
                os.close(directory_fd)

            notes = getattr(caught.exception, "__notes__", [])
            self.assertTrue(
                any("injected unlink failure" in note for note in notes),
                notes,
            )
            self.assertEqual(target.read_bytes(), b"before")
            staged = [
                path for path in directory.iterdir() if path.name != target.name
            ]
            self.assertEqual(len(staged), 1)
            staged[0].unlink()

    def test_pinned_parent_read_cannot_be_redirected_by_symlink_swap(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            trusted = directory / "trusted"
            trusted.mkdir()
            source = trusted / "source.txt"
            source.write_bytes(b"trusted")
            replacement = directory / "replacement"
            replacement.mkdir()
            (replacement / "source.txt").write_bytes(b"redirected")
            displaced = directory / "displaced"

            with RENDERER.open_repository_parent(
                source,
                "test input",
            ) as (directory_fd, name):
                trusted.rename(displaced)
                trusted.symlink_to(replacement.name, target_is_directory=True)
                actual = RENDERER.read_bounded_regular_file_at(
                    directory_fd,
                    name,
                    limit_bytes=64,
                    label="test input",
                    display="trusted/source.txt",
                )

            trusted.unlink()
            displaced.rename(trusted)
            self.assertEqual(actual, b"trusted")

    def test_pinned_output_dir_cannot_be_redirected_by_symlink_swap(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            trusted = directory / "trusted"
            trusted.mkdir()
            (trusted / "artifact.txt").write_bytes(b"before")
            replacement = directory / "replacement"
            replacement.mkdir()
            (replacement / "artifact.txt").write_bytes(b"redirected")
            displaced = directory / "displaced"

            directory_fd = RENDERER.open_repository_directory(
                trusted,
                "visual evidence directory",
            )
            try:
                trusted.rename(displaced)
                trusted.symlink_to(replacement.name, target_is_directory=True)
                RENDERER.atomic_write_at(
                    directory_fd,
                    "artifact.txt",
                    b"after",
                    display="trusted/artifact.txt",
                )
            finally:
                os.close(directory_fd)

            trusted.unlink()
            displaced.rename(trusted)
            self.assertEqual((trusted / "artifact.txt").read_bytes(), b"after")
            self.assertEqual(
                (replacement / "artifact.txt").read_bytes(),
                b"redirected",
            )

    def test_output_inventory_has_a_bounded_entry_count(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            for index in range(RENDERER.MAX_OUTPUT_DIRECTORY_ENTRIES + 1):
                (directory / f"{index:03}.txt").write_bytes(b"x")

            with self.assertRaisesRegex(
                RENDERER.EvidenceError,
                "entry count exceeds the reviewed limit",
            ):
                RENDERER.output_inventory(directory)

    def test_write_outputs_publishes_manifest_last(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            published: list[str] = []
            real_write = RENDERER.atomic_write_at

            def record_write(
                directory_fd: int,
                name: str,
                body: bytes,
                *,
                display: str,
            ) -> None:
                published.append(name)
                real_write(
                    directory_fd,
                    name,
                    body,
                    display=display,
                )

            with mock.patch.object(
                RENDERER,
                "atomic_write_at",
                side_effect=record_write,
            ):
                RENDERER.write_outputs(
                    {
                        "artifact.txt": b"artifact",
                        "manifest.sha256.json": b"manifest",
                    },
                    output_directory=directory,
                    expected_outputs=(
                        "artifact.txt",
                        "manifest.sha256.json",
                    ),
                )

            self.assertEqual(
                published,
                ["artifact.txt", "manifest.sha256.json"],
            )

    def test_mid_bundle_failure_leaves_old_manifest_and_check_fails(
        self,
    ) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            (directory / "artifact-a.txt").write_bytes(b"old-a")
            (directory / "artifact-b.txt").write_bytes(b"old-b")
            manifest = directory / "manifest.sha256.json"
            manifest.write_bytes(b"old-manifest")
            outputs = {
                "artifact-a.txt": b"new-a",
                "artifact-b.txt": b"new-b",
                "manifest.sha256.json": b"new-manifest",
            }
            expected_outputs = tuple(outputs)
            attempted: list[str] = []
            real_write = RENDERER.atomic_write_at

            def fail_mid_bundle(
                directory_fd: int,
                name: str,
                body: bytes,
                *,
                display: str,
            ) -> None:
                attempted.append(name)
                if name == "artifact-b.txt":
                    raise RENDERER.EvidenceError(
                        "injected mid-bundle failure"
                    )
                real_write(
                    directory_fd,
                    name,
                    body,
                    display=display,
                )

            with mock.patch.object(
                RENDERER,
                "atomic_write_at",
                side_effect=fail_mid_bundle,
            ):
                with self.assertRaisesRegex(
                    RENDERER.EvidenceError,
                    "injected mid-bundle failure",
                ):
                    RENDERER.write_outputs(
                        outputs,
                        output_directory=directory,
                        expected_outputs=expected_outputs,
                    )

            self.assertEqual(
                attempted,
                ["artifact-a.txt", "artifact-b.txt"],
            )
            self.assertEqual(
                (directory / "artifact-a.txt").read_bytes(),
                b"new-a",
            )
            self.assertEqual(
                (directory / "artifact-b.txt").read_bytes(),
                b"old-b",
            )
            self.assertEqual(manifest.read_bytes(), b"old-manifest")

            standard_error = io.StringIO()
            with redirect_stderr(standard_error):
                status = RENDERER.check_outputs(
                    outputs,
                    output_directory=directory,
                    expected_outputs=expected_outputs,
                )

            self.assertEqual(status, 1)
            self.assertIn(
                "stale generated files:",
                standard_error.getvalue(),
            )

    def test_write_outputs_rejects_a_late_unexpected_entry(self) -> None:
        with self.temporary_directory() as directory_name:
            directory = Path(directory_name)
            real_write = RENDERER.atomic_write_at

            def write_then_inject(
                directory_fd: int,
                name: str,
                body: bytes,
                *,
                display: str,
            ) -> None:
                real_write(
                    directory_fd,
                    name,
                    body,
                    display=display,
                )
                descriptor = os.open(
                    "late-unexpected.txt",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_fd,
                )
                os.close(descriptor)

            with mock.patch.object(
                RENDERER,
                "atomic_write_at",
                side_effect=write_then_inject,
            ):
                with self.assertRaisesRegex(
                    RENDERER.EvidenceError,
                    "output set changed during publication",
                ):
                    RENDERER.write_outputs(
                        {"artifact.txt": b"artifact"},
                        output_directory=directory,
                        expected_outputs=("artifact.txt",),
                    )


if __name__ == "__main__":
    unittest.main()
