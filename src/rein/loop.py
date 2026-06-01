"""Provider-agnostic steering loop: review, guide, revise, repeat.

The driver is pure - the agent is injected as a Protocol and review/suggest_fix
are pure, so the whole loop is deterministic and testable without a network.
A real integration injects an LLM-backed agent; the example injects a stub.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .core.findings import Finding
from .core.remediation import Remediation, suggest_fix
from .core.review import Policy, ReviewResult, Verdict, review


@dataclass(frozen=True)
class GuidedFinding:
    """A finding paired with its remediation (None when no guidance is known)."""
    finding: Finding
    remediation: Remediation | None


class Agent(Protocol):
    """Anything that can revise code given the findings and their guidance.

    A real implementation formats the guidance into a prompt for an LLM and
    returns the revised source. Implementations must be deterministic enough to
    terminate: return the input unchanged when they cannot make progress.
    """

    def revise(self, code: str, guidance: list[GuidedFinding]) -> str: ...  # rein:ignore lint.stub-body


@dataclass(frozen=True)
class LoopStep:
    iteration: int
    verdict: Verdict
    findings: int


@dataclass(frozen=True)
class LoopOutcome:
    code: str               # final code after the loop
    result: ReviewResult    # final review of that code
    passed: bool            # final verdict is not BLOCK
    iterations: int         # number of revisions the agent actually made
    history: list[LoopStep] # verdict/finding-count per review, including the final


def run_loop(
    code: str,
    agent: Agent,
    *,
    policy: Policy | None = None,
    path: str | None = None,
    max_iterations: int = 5,
) -> LoopOutcome:
    """Drive the steering loop until the review no longer BLOCKs or a bound hits.

    Stops early if the agent returns unchanged code (no progress), so a stuck
    agent cannot spin. Bounded by max_iterations regardless.
    """
    history: list[LoopStep] = []
    result = review(code, path, policy)
    revisions = 0
    while result.verdict is Verdict.BLOCK and revisions < max_iterations:
        history.append(LoopStep(revisions, result.verdict, len(result.findings)))
        guidance = [GuidedFinding(f, suggest_fix(f)) for f in result.findings]
        revised = agent.revise(code, guidance)
        if revised == code:
            break  # agent made no change; stop to avoid spinning
        code = revised
        revisions += 1
        result = review(code, path, policy)
    history.append(LoopStep(revisions, result.verdict, len(result.findings)))
    return LoopOutcome(
        code=code,
        result=result,
        passed=result.verdict is not Verdict.BLOCK,
        iterations=revisions,
        history=history,
    )
