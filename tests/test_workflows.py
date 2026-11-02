import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


def workflow_step_block(workflow: str, step_name: str) -> str:
    source = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    marker = f"      - name: {step_name}\n"
    try:
        start = source.index(marker) + len(marker)
    except ValueError as error:
        raise AssertionError(f"workflow has no {step_name!r} step") from error
    end = source.find("\n      - name: ", start)
    return source[start:] if end == -1 else source[start:end]


def workflow_step_script(workflow: str, step_name: str) -> str:
    block = workflow_step_block(workflow, step_name)
    run_marker = "        run: |\n"
    run_start = block.index(run_marker) + len(run_marker)
    return textwrap.dedent(block[run_start:])


def embedded_python(script: str) -> str:
    match = re.search(r"python3 - <<'PY'\n(.*?)\nPY(?:\n|$)", script, re.DOTALL)
    if match is None:
        raise AssertionError("workflow step has no Python heredoc")
    return match.group(1)


def fake_gh(directory: Path) -> Path:
    executable = directory / "gh"
    executable.write_text(
        """#!/usr/bin/env python3
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with Path(os.environ["GH_LOG"]).open("a", encoding="utf-8") as log:
    log.write(" ".join(args) + "\\n")
if "view" in args:
    if os.environ.get("GH_FAIL") == "view":
        raise SystemExit(1)
    print(os.environ.get("GH_VIEW_OUTPUT", "false"))
elif "--disable-auto" in args and os.environ.get("GH_FAIL") == "disable":
    raise SystemExit(1)
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


class WorkflowTests(unittest.TestCase):
    def test_oidc_step_reports_missing_github_environment(self):
        script = workflow_step_script("gate.yml", "Verify called workflow identity")
        code = embedded_python(script)
        with tempfile.TemporaryDirectory() as tempdir:
            environment = os.environ.copy()
            environment.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
            environment.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)
            environment.pop("ID_TOKEN_REQUEST_URL", None)
            environment.pop("ID_TOKEN_REQUEST_TOKEN", None)
            environment.update(
                {
                    "GITHUB_OUTPUT": str(Path(tempdir) / "output"),
                    "GITHUB_STEP_SUMMARY": str(Path(tempdir) / "summary"),
                }
            )
            result = subprocess.run(
                ["python3", "-c", code],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

            summary = (Path(tempdir) / "summary").read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("GitHub OIDC environment is unavailable", summary)
        self.assertNotIn("KeyError", result.stderr)

    def test_gate_disarm_is_inside_job_and_fails_closed(self):
        workflow = (ROOT / ".github" / "workflows" / "gate.yml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            workflow,
            r"gate:\n(?:.*\n)*?    permissions:\n"
            r"(?:.*\n)*?      pull-requests: write",
        )
        self.assertIn(
            "if: always() && github.event.pull_request.user.login == "
            "'dependabot[bot]' && steps.final.outputs.verdict != 'eligible'",
            workflow,
        )
        script = workflow_step_script("gate.yml", "Disarm stale auto-merge")
        with tempfile.TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            fake_gh(directory)
            log = directory / "gh.log"
            environment = os.environ.copy()
            environment.update(
                {
                    "GH_LOG": str(log),
                    "GH_TOKEN": "test-token",
                    "GH_VIEW_OUTPUT": "true",
                    "GITHUB_REPOSITORY": "owner/repo",
                    "PATH": f"{directory}:{environment['PATH']}",
                    "PR_NUMBER": "17",
                }
            )
            success = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertIn("--disable-auto", log.read_text(encoding="utf-8"))

            for failure in ("view", "disable"):
                with self.subTest(failure=failure):
                    environment["GH_FAIL"] = failure
                    failed = subprocess.run(
                        ["bash", "-c", script],
                        check=False,
                        capture_output=True,
                        env=environment,
                        text=True,
                    )
                    self.assertNotEqual(failed.returncode, 0)

    def test_automerge_rechecks_current_head_before_enabling(self):
        script = workflow_step_script("automerge.yml", "Enable native auto-merge")
        with tempfile.TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            fake_gh(directory)
            log = directory / "gh.log"
            environment = os.environ.copy()
            environment.update(
                {
                    "GH_LOG": str(log),
                    "GH_TOKEN": "test-token",
                    "GH_VIEW_OUTPUT": "b" * 40,
                    "GITHUB_REPOSITORY": "owner/repo",
                    "HEAD_SHA": "a" * 40,
                    "PATH": f"{directory}:{environment['PATH']}",
                    "PR_NUMBER": "17",
                }
            )
            result = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("--auto", log.read_text(encoding="utf-8"))

    def test_non_dependabot_path_skips_oidc_and_checkout(self):
        script = workflow_step_script("gate.yml", "Classify pull request")
        with tempfile.TemporaryDirectory() as tempdir:
            output = Path(tempdir) / "output"
            environment = os.environ.copy()
            environment.update(
                {
                    "GITHUB_OUTPUT": str(output),
                    "HEAD_SHA": "a" * 40,
                    "PR_AUTHOR": "human",
                }
            )
            result = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            outputs = output.read_text(encoding="utf-8")
            self.assertIn("is-dependabot=false", outputs)
            self.assertIn("verdict=not-dependency", outputs)

        identity = workflow_step_block("gate.yml", "Verify called workflow identity")
        self.assertIn(
            "if: steps.context.outputs.is-dependabot == 'true'", identity
        )
        for step_name in (
            "Check out gate implementation",
            "Check out base as data",
            "Check out head as data",
            "Fetch commit and file metadata",
            "Read Dependabot metadata",
            "Save Dependabot metadata as data",
            "Evaluate dependency gate",
        ):
            with self.subTest(step=step_name):
                block = workflow_step_block("gate.yml", step_name)
                self.assertIn(
                    "if: steps.identity.outputs.verified == 'true'", block
                )

    def test_dependabot_missing_oidc_becomes_ineligible_without_step_failure(self):
        script = workflow_step_script("gate.yml", "Verify called workflow identity")
        code = embedded_python(script)
        with tempfile.TemporaryDirectory() as tempdir:
            output = Path(tempdir) / "output"
            summary = Path(tempdir) / "summary"
            environment = os.environ.copy()
            environment.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
            environment.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)
            environment.update(
                {
                    "GITHUB_OUTPUT": str(output),
                    "GITHUB_STEP_SUMMARY": str(summary),
                }
            )
            result = subprocess.run(
                ["python3", "-c", code],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            outputs = output.read_text(encoding="utf-8")
            self.assertIn("verified=false", outputs)
            self.assertIn("verdict=ineligible", outputs)
            self.assertIn(
                "could not verify called workflow identity",
                summary.read_text(encoding="utf-8"),
            )

    def test_identity_failure_flows_to_final_verdict(self):
        script = workflow_step_script("gate.yml", "Finalize verdict")
        with tempfile.TemporaryDirectory() as tempdir:
            output = Path(tempdir) / "output"
            environment = os.environ.copy()
            environment.update(
                {
                    "CONTEXT_VERDICT": "",
                    "EVALUATED_VERDICT": "",
                    "GITHUB_OUTPUT": str(output),
                    "IDENTITY_VERDICT": "ineligible",
                }
            )
            result = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("verdict=ineligible", output.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
