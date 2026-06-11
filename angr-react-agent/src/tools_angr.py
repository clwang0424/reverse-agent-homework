"""angr-backed tools used by the ReAct orchestration loop."""

from __future__ import annotations

from pathlib import Path
from typing import Any
import uuid

import angr
import claripy


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BINARY = PROJECT_ROOT / "crackme"

SUCCESS_TEXT = b"Success! Flag is found."
WRONG_TEXT = b"Wrong password!"
TRAP_TEXT = b"Oops! You are trapped in a dead loop."

_SUCCESS_STATES: dict[str, tuple[Any, Any]] = {}


def _binary_path(binary_path: str | Path | None) -> Path:
    path = Path(binary_path) if binary_path else DEFAULT_BINARY
    path = path.expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(
            f"Binary not found at {path}. Build it with: gcc crackme.c -o crackme"
        )
    return path


def _find_bytes(project: angr.Project, needle: bytes) -> list[str]:
    """Find mapped addresses containing a byte string."""
    addresses: list[str] = []
    for obj in project.loader.all_objects:
        for section in obj.sections:
            if not section.is_readable or section.memsize <= 0:
                continue
            try:
                data = project.loader.memory.load(section.vaddr, section.memsize)
            except KeyError:
                continue
            offset = data.find(needle)
            while offset != -1:
                addresses.append(hex(section.vaddr + offset))
                offset = data.find(needle, offset + 1)
    return addresses


def inspect_binary(binary_path: str | Path | None = None) -> dict[str, Any]:
    """Load the crackme and return architecture, symbols, and string evidence."""
    path = _binary_path(binary_path)
    project = angr.Project(str(path), auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True)

    preferred = {"main", "check_password", "gadget_trap"}
    functions = []
    for function in cfg.kb.functions.values():
        if function.name in preferred or not function.name.startswith("sub_"):
            functions.append({"name": function.name, "address": hex(function.addr)})
    functions = sorted(
        functions,
        key=lambda item: (
            item["name"] not in preferred,
            item["name"],
            item["address"],
        ),
    )[:40]

    strings = {
        SUCCESS_TEXT.decode(): _find_bytes(project, SUCCESS_TEXT),
        WRONG_TEXT.decode(): _find_bytes(project, WRONG_TEXT),
        TRAP_TEXT.decode(): _find_bytes(project, TRAP_TEXT),
    }

    return {
        "binary": f"./{path.name}",
        "architecture": project.arch.name,
        "bits": project.arch.bits,
        "entry_address": hex(project.entry),
        "functions": functions,
        "string_addresses": strings,
    }


def explore_success_path(binary_path: str | Path | None = None) -> dict[str, Any]:
    """Explore symbolic stdin toward success while avoiding failure and the trap."""
    path = _binary_path(binary_path)
    project = angr.Project(str(path), auto_load_libs=False)

    # scanf("%9s") consumes four symbolic printable bytes followed by a newline.
    symbolic_input = claripy.BVS("password", 4 * 8)
    stdin = angr.SimFileStream(
        name="stdin",
        content=claripy.Concat(symbolic_input, claripy.BVV(b"\n")),
        has_end=True,
    )
    state = project.factory.full_init_state(args=[str(path)], stdin=stdin)
    for byte in symbolic_input.chop(8):
        state.solver.add(byte >= 0x21, byte <= 0x7E)

    simulation = project.factory.simgr(state)
    simulation.explore(
        find=lambda candidate: SUCCESS_TEXT in candidate.posix.dumps(1),
        avoid=lambda candidate: (
            WRONG_TEXT in candidate.posix.dumps(1)
            or TRAP_TEXT in candidate.posix.dumps(1)
        ),
    )

    if not simulation.found:
        return {
            "found": False,
            "found_states": 0,
            "active_states": len(simulation.active),
            "deadended_states": len(simulation.deadended),
            "avoided_states": len(simulation.avoid),
            "message": "No state reached the success output.",
        }

    found_state = simulation.found[0]
    state_id = uuid.uuid4().hex
    _SUCCESS_STATES[state_id] = (found_state, symbolic_input)
    preview = found_state.solver.eval(symbolic_input, cast_to=bytes)

    return {
        "found": True,
        "state_id": state_id,
        "found_states": len(simulation.found),
        "active_states": len(simulation.active),
        "deadended_states": len(simulation.deadended),
        "avoided_states": len(simulation.avoid),
        "stdout": found_state.posix.dumps(1).decode(errors="replace"),
        "input_preview_hex": preview.hex(),
        "constraints": len(found_state.solver.constraints),
    }


def solve_input(state_id: str) -> dict[str, Any]:
    """Concretize the symbolic password retained by explore_success_path."""
    if state_id not in _SUCCESS_STATES:
        raise KeyError(f"Unknown success state: {state_id}")

    state, symbolic_input = _SUCCESS_STATES[state_id]
    password = state.solver.eval(symbolic_input, cast_to=bytes)
    return {
        "solved": True,
        "password": password.decode("ascii"),
        "password_hex": password.hex(),
        "length": len(password),
    }
