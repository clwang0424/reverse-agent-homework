"""A small ReAct-style orchestrator for the angr reverse-analysis tools."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable

from tools_angr import explore_success_path, inspect_binary, solve_input


class ReactAgent:
    """Run three Thought -> Action -> Observation rounds.

    The default mode is deterministic so the lab is runnable without secrets.
    When OPENAI_API_KEY is present, an OpenAI model may rewrite each planning
    thought while the same auditable angr tool sequence remains in force.
    """

    def __init__(self, binary_path: Path, log_path: Path) -> None:
        self.binary_path = binary_path.resolve()
        self.log_path = log_path.resolve()
        self.use_llm = bool(os.getenv("OPENAI_API_KEY"))

    def _thought(self, fallback: str, context: dict[str, Any]) -> str:
        if not self.use_llm:
            return fallback

        try:
            from openai import OpenAI

            response = OpenAI().responses.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
                input=(
                    "Write one concise ReAct Thought for a reverse-analysis lab. "
                    "Do not invent observations. Planned reasoning: "
                    f"{fallback}\nKnown context: {json.dumps(context, default=str)}"
                ),
            )
            return response.output_text.strip() or fallback
        except Exception as exc:
            return f"{fallback} [LLM unavailable; deterministic fallback: {exc}]"

    @staticmethod
    def _render(value: Any) -> str:
        return json.dumps(value, indent=2, sort_keys=True, default=str)

    def _round(
        self,
        number: int,
        thought: str,
        action: str,
        tool: Callable[..., dict[str, Any]],
        context: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        planned_thought = self._thought(thought, context)
        observation = tool(**kwargs)
        context[f"round_{number}"] = observation
        self._entries.append(
            f"Round {number}\n"
            f"Thought: {planned_thought}\n"
            f"Action: {action}\n"
            f"Observation:\n{self._render(observation)}\n"
        )
        return observation

    def run(self) -> dict[str, Any]:
        self._entries: list[str] = []
        context: dict[str, Any] = {}

        inspection = self._round(
            1,
            "Identify the binary's success, failure, and trap semantics before exploring.",
            "inspect_binary('./crackme')",
            inspect_binary,
            context,
            binary_path=self.binary_path,
        )

        exploration = self._round(
            2,
            "Use the discovered success and trap evidence as find/avoid goals for symbolic execution.",
            "explore_success_path('./crackme')",
            explore_success_path,
            context,
            binary_path=self.binary_path,
        )
        if not exploration.get("found"):
            raise RuntimeError("angr did not find a success state")

        solution = self._round(
            3,
            "Concretize the symbolic stdin retained in the successful state.",
            f"solve_input({exploration['state_id']})",
            solve_input,
            context,
            state_id=exploration["state_id"],
        )

        mode = "OpenAI-assisted thoughts" if self.use_llm else "deterministic ReAct thoughts"
        header = f"ReAct + angr execution log\nMode: {mode}\nBinary: ./crackme\n\n"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text(header + "\n".join(self._entries), encoding="utf-8")
        return {
            "inspection": inspection,
            "exploration": exploration,
            "solution": solution,
            "log_path": str(self.log_path),
            "mode": mode,
        }
