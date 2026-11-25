#!/usr/bin/env python3
"""Give the repository-scoped MacBook runner a bounded chance to run pytest."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from typing import Any, Callable

REPOSITORY = "aiconnai/smart-ads"
WORKFLOW = "local-pytest.yml"
RUNNER = "macbook-ci-1"
AUTHORIZE_JOB = "Validate CI source"
TEST_JOB = "Run pytest on MacBook"
TEST_STEP = "Record test failure"
QUEUE_SECONDS = 75
TEST_SECONDS = 40 * 60


class APIError(RuntimeError):
    pass


def api(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    command = [
        "gh",
        "api",
        "--method",
        method,
        "-H",
        "X-GitHub-Api-Version: 2026-03-10",
        f"repos/{REPOSITORY}/{endpoint}",
    ]
    if payload is not None:
        command.extend(("--input", "-"))
    try:
        response = subprocess.run(
            command,
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True,
            text=True,
            timeout=12,
            check=True,
        )
        data = json.loads(response.stdout) if response.stdout else {}
        if not isinstance(data, dict):
            raise APIError(f"{method} GitHub Actions response was not an object")
        return data
    except (subprocess.SubprocessError, OSError, ValueError):
        raise APIError(f"{method} GitHub Actions request failed") from None


def test_outcome(job: dict[str, Any]) -> str:
    if job.get("runner_name") != RUNNER:
        return "fallback"
    if job.get("conclusion") == "success":
        return "success"
    if job.get("conclusion") == "failure" and any(
        step.get("name") == TEST_STEP and step.get("conclusion") == "failure"
        for step in job.get("steps", [])
    ):
        return "test-failed"
    return "fallback"


def route(
    payload: dict[str, Any],
    *,
    request: Callable[..., dict[str, Any]] = api,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[str, str]:
    try:
        response = request("POST", f"actions/workflows/{WORKFLOW}/dispatches", payload)
        run_id = response.get("workflow_run_id")
        if type(run_id) is not int or run_id <= 0:
            raise APIError("GitHub did not return a worker run ID")
    except APIError as error:
        print(f"MacBook CI fallback: {error}", flush=True)
        return "fallback", ""

    run_url = f"https://github.com/{REPOSITORY}/actions/runs/{run_id}"
    print(f"MacBook CI worker: {run_url}", flush=True)
    deadline = clock() + QUEUE_SECONDS
    started = False
    terminal = False
    try:
        while clock() < deadline:
            try:
                jobs = request("GET", f"actions/runs/{run_id}/jobs").get("jobs", [])
            except APIError:
                jobs = []
            job = next((item for item in jobs if item.get("name") == TEST_JOB), {})
            if job.get("status") == "completed":
                terminal = True
                return test_outcome(job), run_url
            if (
                not started
                and job.get("status") == "in_progress"
                and job.get("runner_name") == RUNNER
            ):
                started = True
                deadline = clock() + TEST_SECONDS
            if any(
                item.get("name") == AUTHORIZE_JOB
                and item.get("status") == "completed"
                and item.get("conclusion") != "success"
                for item in jobs
            ):
                return "fallback", run_url
            sleep(min(5, max(0.0, deadline - clock())))
        print("MacBook CI fallback: local execution deadline elapsed", flush=True)
        return "fallback", run_url
    finally:
        if not terminal:
            try:
                request("POST", f"actions/runs/{run_id}/cancel")
            except APIError:
                print(
                    "::warning::Could not confirm cancellation of the MacBook CI worker",
                    flush=True,
                )


def _interrupt(_signum: int, _frame: Any) -> None:
    raise KeyboardInterrupt


def main() -> None:
    signal.signal(signal.SIGTERM, _interrupt)
    payload = {
        "ref": "main",
        "return_run_details": True,
        "inputs": {
            "ci_run_id": os.environ["CI_RUN_ID"],
            "ci_attempt": os.environ["CI_RUN_ATTEMPT"],
            "source_sha": os.environ["CI_SOURCE_SHA"],
            "pr_number": os.environ.get("CI_PR_NUMBER") or "0",
        },
    }
    outcome, run_url = route(payload)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        print(f"outcome={outcome}\nrun_url={run_url}", file=output)


if __name__ == "__main__":
    main()
