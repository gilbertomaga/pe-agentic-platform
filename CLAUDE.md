# pe-agentic-platform

Agent runtime, policy layer, audit trail and golden path. Python, Docker, OPA.

## Layout

- `runtime/` sandbox lifecycle, one container per run
- `policy/` OPA policies and the evaluation entry point
- `trail/` append only JSONL writer and the audit gate
- `golden_path/` provisioning that wires the three together
- `docs/decisions.md` decision log, read this before changing behaviour

## Running

    python -m pytest -q
    python -m runtime <plan-file>

## Rules

- No client code, credentials or account identifiers in this repo.
- Policy denies by default. Every denial carries a reason.
- The trail is written by the platform, never by the caller.
- Nothing in here may modify `policy/`.
