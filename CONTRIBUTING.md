# Contributing

Thanks for your interest in PipSutra.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Before submitting a change

```bash
ruff check .
ruff format --check .
mypy src/pipsutra
pytest
```

Add tests for bug fixes and new behavior. Keep findings evidence-based and avoid
claiming that a package is malicious from a single weak indicator.

## Contributions and licensing

By intentionally submitting a contribution for inclusion, you agree that it is
submitted under the project's Apache License 2.0, subject to any separate written
agreement. You retain copyright in your contribution.
