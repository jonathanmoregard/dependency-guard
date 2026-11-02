import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


def workflow_step_script(workflow: str, step_name: str) -> str:
    source = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    marker = f"      - name: {step_name}\n"
    start = source.index(marker) + len(marker)
    end = source.find("\n      - name: ", start)
    block = source[start:] if end == -1 else source[start:end]
    run_marker = "        run: |\n"
    run_start = block.index(run_marker) + len(run_marker)
    return textwrap.dedent(block[run_start:])


def embedded_python(script: str) -> str:
    match = re.search(r"python3 - <<'PY'\n(.*?)\nPY(?:\n|$)", script, re.DOTALL)
    if match is None:
        raise AssertionError("workflow step has no Python heredoc")
    return match.group(1)


class WorkflowTests(unittest.TestCase):
    def test_oidc_step_reports_missing_github_environment(self):
        script = workflow_step_script("gate.yml", "Record trusted context")
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
                    "HEAD_SHA": "a" * 40,
                }
            )
            result = subprocess.run(
                ["python3", "-c", code],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GitHub OIDC environment is unavailable", result.stderr)
        self.assertNotIn("KeyError", result.stderr)


if __name__ == "__main__":
    unittest.main()
