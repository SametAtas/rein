"""Tests for the provider-agnostic agent-loop driver."""

from __future__ import annotations

from rein.loop import GuidedFinding, run_loop


class FixingAgent:
    def revise(self, code: str, guidance: list[GuidedFinding]) -> str:
        return code.replace("yaml.load(", "yaml.safe_load(")


class NoProgressAgent:
    def revise(self, code: str, guidance: list[GuidedFinding]) -> str:
        return code


class InfiniteAgent:
    def revise(self, code: str, guidance: list[GuidedFinding]) -> str:
        return code + "\n# nudge"


class UnreachableAgent:
    def __init__(self) -> None:
        self.called = False

    def revise(self, code: str, guidance: list[GuidedFinding]) -> str:
        self.called = True
        return code


def test_run_loop_converges() -> None:
    start = "import yaml\nyaml.load(x)\n"
    outcome = run_loop(start, FixingAgent(), path="m.py")
    assert outcome.passed is True
    assert outcome.iterations == 1
    assert "safe_load" in outcome.code


def test_run_loop_already_clean() -> None:
    agent = UnreachableAgent()
    outcome = run_loop("x = 1\n", agent, path="m.py")
    assert outcome.passed is True
    assert outcome.iterations == 0
    assert not agent.called


def test_run_loop_stops_on_no_progress() -> None:
    start = "import yaml\nyaml.load(x)\n"
    outcome = run_loop(start, NoProgressAgent(), path="m.py")
    assert outcome.passed is False
    assert outcome.iterations == 0
    assert len(outcome.history) == 2  # initial review + stop after 0 iterations


def test_run_loop_bounded_by_max_iterations() -> None:
    start = "import yaml\nyaml.load(x)\n"
    outcome = run_loop(start, InfiniteAgent(), path="m.py", max_iterations=3)
    assert outcome.passed is False
    assert outcome.iterations == 3
    assert outcome.code.count("nudge") == 3
    assert len(outcome.history) == 4  # initial review + 3 revisions
