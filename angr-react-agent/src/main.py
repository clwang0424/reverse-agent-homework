"""Command-line entry point for the ReAct + angr lab."""

from __future__ import annotations

import json
from pathlib import Path

from react_agent import ReactAgent


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    agent = ReactAgent(
        binary_path=PROJECT_ROOT / "crackme",
        log_path=PROJECT_ROOT / "logs" / "run.txt",
    )
    result = agent.run()
    print(json.dumps(result["solution"], indent=2))
    print(f"Execution log: {result['log_path']}")


if __name__ == "__main__":
    main()
