"""Runnable demo of the rein steering loop with a deterministic stub agent.

Run: python examples/guarded_agent.py
The stub applies known mechanical fixes (no network). A real integration would
replace MechanicalFixAgent with an LLM-backed Agent.
"""

from __future__ import annotations

from rein.loop import Agent, GuidedFinding, run_loop

# rule_id -> (unsafe substring, safe replacement) for the mechanical fixes the stub knows.
_FIXES: dict[str, tuple[str, str]] = {
    "security.yaml-unsafe-load": ("yaml.load(", "yaml.safe_load("),
    "security.weak-hash": ("hashlib.md5(", "hashlib.sha256("),
}


class MechanicalFixAgent:
    """A stub agent that applies known string-level fixes for guided findings."""

    def revise(self, code: str, guidance: list[GuidedFinding]) -> str:
        for guided in guidance:
            swap = _FIXES.get(guided.finding.rule_id)
            if swap is not None:
                code = code.replace(*swap)
        return code


def main() -> int:
    start = "import yaml\nconfig = yaml.load(raw)\n"
    agent: Agent = MechanicalFixAgent()
    outcome = run_loop(start, agent, path="config_loader.py")
    for step in outcome.history:
        print(f"  iter {step.iteration}: {step.verdict} ({step.findings} finding(s))")
    print(f"passed={outcome.passed} after {outcome.iterations} revision(s)")
    print("--- final code ---")
    print(outcome.code, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
