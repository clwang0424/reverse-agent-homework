# ReAct Agent + angr Reverse-Analysis Lab

This project uses a ReAct-style orchestration loop and callable angr tools to
inspect and solve the included crackme.

## Requirements

- Python 3.10 or 3.11 recommended
- GCC

Create a virtual environment and install the dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Build

From the `angr-react-agent` directory:

```bash
gcc crackme.c -o crackme
```

The checked-in binary was built from the exact `crackme.c` in this directory.

## Run

```bash
python src/main.py
```

Expected outputs:

- `logs/run.txt`: three real Thought -> Action -> Observation rounds
- `report.md`: experiment description and result

The default run is deterministic and requires no API key. It preserves the
ReAct structure while all observations come from real angr calls. If
`OPENAI_API_KEY` is already configured, the agent can use the OpenAI API to
word the planning thoughts; keys and `.env` files must not be committed.
