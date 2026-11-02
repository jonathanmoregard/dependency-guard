import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


def workflow_step_block(workflow: str, step_name: str) -> str:
    path = ROOT / ".github" / "workflows" / workflow
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        raise AssertionError(f"workflow does not exist: {workflow}") from error
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
elif args[:2] == ["pr", "list"]:
    print(os.environ.get("GH_PR_LIST_OUTPUT", ""))
elif args[:2] == ["run", "list"]:
    print(os.environ.get("GH_RUN_LIST_OUTPUT", ""))
elif "--disable-auto" in args and os.environ.get("GH_FAIL") == "disable":
    raise SystemExit(1)
elif "comment" in args and os.environ.get("GH_FAIL") == "comment":
    raise SystemExit(1)
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


class WorkflowTests(unittest.TestCase):
    def test_finalize_marks_only_cooldown_reasons_retryable(self):
        script = workflow_step_script("gate.yml", "Finalize verdict")
        cases = (
            (
                ["pkg@1.0.1 has not completed its 72h cooldown"],
                "true",
            ),
            (
                [
                    "pkg@1.0.1 has not completed its 72h cooldown",
                    "same-version entry changed: transitive",
                ],
                "false",
            ),
        )
        for reasons, expected in cases:
            with self.subTest(reasons=reasons), tempfile.TemporaryDirectory() as tempdir:
                directory = Path(tempdir)
                (directory / "verdict.json").write_text(
                    json.dumps({"verdict": "ineligible", "reasons": reasons}),
                    encoding="utf-8",
                )
                output = directory / "output"
                environment = os.environ.copy()
                environment.update(
                    {
                        "CONTEXT_VERDICT": "",
                        "EVALUATED_VERDICT": "ineligible",
                        "GITHUB_OUTPUT": str(output),
                        "IDENTITY_REASON": "",
                        "IDENTITY_VERDICT": "",
                        "RUNNER_TEMP": str(directory),
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
                self.assertIn(
                    f"cooldown-only={expected}",
                    output.read_text(encoding="utf-8"),
                )

    def test_gate_reconciles_cooldown_retry_label(self):
        script = workflow_step_script("gate.yml", "Update cooldown retry label")
        with tempfile.TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            fake_gh(directory)
            log = directory / "gh.log"
            environment = os.environ.copy()
            environment.update(
                {
                    "GH_LOG": str(log),
                    "GH_TOKEN": "test-token",
                    "GITHUB_REPOSITORY": "owner/repo",
                    "PATH": f"{directory}:{environment['PATH']}",
                    "PR_NUMBER": "17",
                }
            )

            environment["COOLDOWN_ONLY"] = "true"
            added = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            self.assertEqual(added.returncode, 0, added.stderr)
            self.assertIn(
                "--add-label dependency-guard:cooldown",
                log.read_text(encoding="utf-8"),
            )

            log.write_text("", encoding="utf-8")
            environment.update({"COOLDOWN_ONLY": "false", "GH_VIEW_OUTPUT": "true"})
            removed = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertIn(
                "--remove-label dependency-guard:cooldown",
                log.read_text(encoding="utf-8"),
            )

    def test_retry_workflow_reruns_latest_gate_for_current_heads(self):
        script = workflow_step_script("retry.yml", "Retry cooldown pull requests")
        with tempfile.TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            fake_gh(directory)
            log = directory / "gh.log"
            pull_requests = "\n".join(
                f"{number}\t{number:040x}" for number in range(1, 21)
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "GH_LOG": str(log),
                    "GH_PR_LIST_OUTPUT": pull_requests,
                    "GH_RUN_LIST_OUTPUT": "9001",
                    "GH_TOKEN": "test-token",
                    "GITHUB_REPOSITORY": "owner/repo",
                    "PATH": f"{directory}:{environment['PATH']}",
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
            calls = log.read_text(encoding="utf-8").splitlines()
            reruns = [call for call in calls if call.startswith("run rerun ")]
            self.assertEqual(len(reruns), 20)
            self.assertTrue(
                all(
                    call == "run rerun 9001 --repo owner/repo"
                    for call in reruns
                )
            )
            for number in range(1, 21):
                self.assertTrue(
                    any(
                        call.startswith("run list ")
                        and f"--commit {number:040x}" in call
                        for call in calls
                    )
                )

    def test_retry_workflow_and_caller_are_least_privilege_and_bounded(self):
        retry_path = ROOT / ".github" / "workflows" / "retry.yml"
        self.assertTrue(retry_path.exists(), "retry workflow must exist")
        retry = retry_path.read_text(encoding="utf-8")
        self.assertIn("on:\n  workflow_call:", retry)
        self.assertIn("permissions: {}", retry)
        self.assertRegex(
            retry,
            r"retry:\n(?:.*\n)*?    permissions:\n"
            r"      actions: write\n"
            r"      pull-requests: read\n"
            r"      contents: read",
        )
        self.assertNotIn("actions/checkout@", retry)
        self.assertIn("--limit 20", retry)

        caller = (ROOT / "templates" / "dependency-guard.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('cron: "17 */6 * * *"', caller)
        self.assertIn("workflow_dispatch:", caller)
        self.assertIn("if: github.event_name == 'pull_request'", caller)
        self.assertIn(
            "if: github.event_name == 'schedule' || "
            "github.event_name == 'workflow_dispatch'",
            caller,
        )
        self.assertRegex(
            caller,
            r"uses: jonathanmoregard/dependency-guard/\.github/workflows/"
            r"retry\.yml@[0-9a-f]{40}",
        )

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
        finalize = workflow_step_script("gate.yml", "Finalize verdict")
        with tempfile.TemporaryDirectory() as tempdir:
            directory = Path(tempdir)
            fake_gh(directory)
            log = directory / "gh.log"
            (directory / "verdict.json").write_text(
                '{"verdict":"ineligible","reasons":["more than one commit"]}',
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "CONTEXT_VERDICT": "",
                    "EVALUATED_VERDICT": "ineligible",
                    "GITHUB_OUTPUT": str(directory / "output"),
                    "GH_LOG": str(log),
                    "GH_TOKEN": "test-token",
                    "GH_VIEW_OUTPUT": "true",
                    "GITHUB_REPOSITORY": "owner/repo",
                    "IDENTITY_REASON": "",
                    "IDENTITY_VERDICT": "",
                    "PATH": f"{directory}:{environment['PATH']}",
                    "PR_NUMBER": "17",
                    "RUNNER_TEMP": str(directory),
                    "VERDICT": "ineligible",
                }
            )
            finalized = subprocess.run(
                ["bash", "-c", finalize],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            success = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            self.assertEqual(success.returncode, 0, success.stderr)
            calls = log.read_text(encoding="utf-8").splitlines()
            self.assertTrue(any("--disable-auto" in call for call in calls))
            comments = [call for call in calls if "pr comment" in call]
            self.assertEqual(len(comments), 1)
            self.assertIn("ineligible", comments[0])
            self.assertIn("more than one commit", comments[0])

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

            environment["GH_FAIL"] = "comment"
            comment_failed = subprocess.run(
                ["bash", "-c", script],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            self.assertEqual(comment_failed.returncode, 0, comment_failed.stderr)

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

    def test_gate_reads_actor_from_workflow_context(self):
        evaluate = workflow_step_block("gate.yml", "Evaluate dependency gate")

        self.assertIn("ACTOR: ${{ github.actor }}", evaluate)

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
                    "IDENTITY_REASON": "could not verify called workflow identity",
                    "IDENTITY_VERDICT": "ineligible",
                    "RUNNER_TEMP": str(Path(tempdir)),
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
            self.assertEqual(
                (Path(tempdir) / "dependency-guard-reason.txt").read_text(
                    encoding="utf-8"
                ),
                "could not verify called workflow identity",
            )


if __name__ == "__main__":
    unittest.main()
