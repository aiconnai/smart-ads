from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tools.ci import local_pytest_router as router

REPO_ROOT = Path(__file__).resolve().parents[2]


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def test_route_returns_success_when_macbook_runner_passes() -> None:
    calls: list[tuple[str, str]] = []
    polls = [
        {"jobs": [{"name": router.TEST_JOB, "status": "in_progress", "runner_name": router.RUNNER}]},
        {
            "jobs": [
                {
                    "name": router.TEST_JOB,
                    "status": "completed",
                    "conclusion": "success",
                    "runner_name": router.RUNNER,
                }
            ]
        },
    ]

    def fake_request(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        calls.append((method, endpoint))
        if method == "POST" and endpoint.endswith("/dispatches"):
            return {"workflow_run_id": 12345}
        if method == "GET" and endpoint == "actions/runs/12345/jobs":
            return polls.pop(0)
        raise AssertionError(f"Unexpected call: {method} {endpoint}")

    clock = _FakeClock()
    outcome, url = router.route({"ref": "main"}, request=fake_request, clock=clock, sleep=clock.sleep)
    assert outcome == "success"
    assert url == f"https://github.com/{router.REPOSITORY}/actions/runs/12345"
    assert not any(endpoint.endswith("/cancel") for _, endpoint in calls)


def test_route_returns_test_failed_when_record_step_fails() -> None:
    def fake_request(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if method == "POST" and endpoint.endswith("/dispatches"):
            return {"workflow_run_id": 77}
        if method == "GET" and endpoint == "actions/runs/77/jobs":
            return {
                "jobs": [
                    {
                        "name": router.TEST_JOB,
                        "status": "completed",
                        "conclusion": "failure",
                        "runner_name": router.RUNNER,
                        "steps": [{"name": router.TEST_STEP, "conclusion": "failure"}],
                    }
                ]
            }
        raise AssertionError(f"Unexpected call: {method} {endpoint}")

    clock = _FakeClock()
    outcome, url = router.route({"ref": "main"}, request=fake_request, clock=clock, sleep=clock.sleep)
    assert outcome == "test-failed"
    assert url == f"https://github.com/{router.REPOSITORY}/actions/runs/77"


def test_route_falls_back_on_infra_failure_or_wrong_runner() -> None:
    assert (
        router.test_outcome(
            {
                "runner_name": router.RUNNER,
                "conclusion": "failure",
                "steps": [{"name": "Run actions/checkout@v4", "conclusion": "failure"}],
            }
        )
        == "fallback"
    )
    assert (
        router.test_outcome(
            {
                "runner_name": "other-runner",
                "conclusion": "success",
            }
        )
        == "fallback"
    )


def test_route_cancels_and_falls_back_when_queue_deadline_elapses() -> None:
    cancelled = False

    def fake_request(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        nonlocal cancelled
        if method == "POST" and endpoint.endswith("/dispatches"):
            return {"workflow_run_id": 88}
        if method == "GET" and endpoint == "actions/runs/88/jobs":
            return {"jobs": [{"name": router.TEST_JOB, "status": "queued", "runner_name": None}]}
        if method == "POST" and endpoint == "actions/runs/88/cancel":
            cancelled = True
            return {}
        raise AssertionError(f"Unexpected call: {method} {endpoint}")

    clock = _FakeClock()
    outcome, url = router.route({"ref": "main"}, request=fake_request, clock=clock, sleep=clock.sleep)
    assert outcome == "fallback"
    assert url == f"https://github.com/{router.REPOSITORY}/actions/runs/88"
    assert cancelled is True
    assert clock.now >= router.QUEUE_SECONDS


def test_route_cancels_and_falls_back_when_authorization_fails() -> None:
    cancelled = False

    def fake_request(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        nonlocal cancelled
        if method == "POST" and endpoint.endswith("/dispatches"):
            return {"workflow_run_id": 99}
        if method == "GET" and endpoint == "actions/runs/99/jobs":
            return {
                "jobs": [
                    {
                        "name": router.AUTHORIZE_JOB,
                        "status": "completed",
                        "conclusion": "failure",
                    }
                ]
            }
        if method == "POST" and endpoint == "actions/runs/99/cancel":
            cancelled = True
            return {}
        raise AssertionError(f"Unexpected call: {method} {endpoint}")

    clock = _FakeClock()
    outcome, url = router.route({"ref": "main"}, request=fake_request, clock=clock, sleep=clock.sleep)
    assert outcome == "fallback"
    assert url == f"https://github.com/{router.REPOSITORY}/actions/runs/99"
    assert cancelled is True


def test_route_falls_back_when_dispatch_fails_or_missing_run_id() -> None:
    def failing_request(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        raise router.APIError("dispatch unavailable")

    def empty_run_id_request(method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"workflow_run_id": None}

    clock = _FakeClock()
    assert router.route({"ref": "main"}, request=failing_request, clock=clock, sleep=clock.sleep) == (
        "fallback",
        "",
    )
    assert router.route({"ref": "main"}, request=empty_run_id_request, clock=clock, sleep=clock.sleep) == (
        "fallback",
        "",
    )


def test_api_raises_api_error_on_non_object_json(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Completed:
        stdout = "[]"

    monkeypatch.setattr(router.subprocess, "run", lambda *args, **kwargs: _Completed())
    with pytest.raises(router.APIError, match="GitHub Actions response was not an object"):
        router.api("GET", "actions/runs/1/jobs")


def test_workflows_preserve_required_check_and_public_repo_guards() -> None:
    pytest_wf = (REPO_ROOT / ".github" / "workflows" / "pytest.yml").read_text(encoding="utf-8")
    local_wf = (REPO_ROOT / ".github" / "workflows" / "local-pytest.yml").read_text(encoding="utf-8")

    for token in (
        "name: pytest",
        "try-local:",
        "github.event.pull_request.head.repo.full_name == github.repository",
        "github.event.pull_request.draft == false",
        "persist-credentials: false",
        "tools/ci/local_pytest_router.py",
        "if: ${{ !cancelled() }}",
    ):
        assert token in pytest_wf

    for token in (
        "permissions: {}",
        "workflow_dispatch:",
        "github.repository == 'aiconnai/smart-ads' && github.ref == 'refs/heads/main'",
        "runs-on: [self-hosted, Linux, ARM64, macbook-4c-4g]",
        "persist-credentials: false",
        "Record test failure",
    ):
        assert token in local_wf
