# PipSutra

**Know what your dependencies bring into your project.**

**Developed by Nikhil Mutreja.**

PipSutra is an early-stage dependency trust inspector for Python projects. It
inventories the selected environment, checks installed project dependencies
against the [OSV vulnerability database](https://osv.dev/), and applies a small
set of transparent Python AST rules to project source code. It is developed by
Nikhil Mutreja with a focus on explainable evidence rather than opaque
“safe/unsafe” verdicts.

> **Release scope:** v0.1.0 is an alpha release. Its checks are useful signals,
> not proof that a project or package is safe. Static rules can produce false
> positives and false negatives. Vulnerability results depend on OSV data and
> network availability. Package provenance/attestation verification,
> lockfile-native resolution, dynamic analysis, and malware verdicts are not
> included in this release.

## What it checks

| Capability | v0.1.0 behavior |
|---|---|
| Dependency inventory | Reads `requirements.txt`, `pyproject.toml`, and installed distribution metadata |
| Dependency graph | Infers edges from installed `Requires-Dist` metadata |
| Vulnerabilities | Queries OSV for exact installed versions of direct and reachable dependencies |
| Source checks | Applies documented AST rules to Python files in the selected project |
| Reports | Terminal summary and versioned JSON report |
| Risk summary | Transparent heuristic for prioritization; not a probability or safety verdict |

### Static rules

- `DG-PY-001`: calls to `eval()` or `exec()` — dynamic code execution.
- `DG-PY-002`: `os.system()` — shell-mediated command execution.
- `DG-PY-003`: subprocess calls with the literal `shell=True`.
- `DG-PY-004`: `pickle.loads()` — unsafe if input is untrusted.

These rules identify code patterns, not malicious intent. The `confidence` field
expresses confidence that the syntactic pattern was detected; it is not a
confidence score that the code is malicious or exploitable. For example, `eval()`
may be used in a constrained internal context, and a finding does not prove an
exploitable vulnerability. Conversely, the absence of findings does not prove
that source code is safe. The initial rules do not perform taint analysis,
interprocedural analysis, alias resolution, or semantic sandboxing.

## Install

Python 3.11 or newer is required.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
python -m pip install pipsutra

# Verify the installed version and developer attribution
pipsutra version
```

For development from a source checkout:

```bash
python -m pip install -e ".[dev]"
```

## Quick start

Run a complete scan (OSV requires an internet connection):

```bash
pipsutra scan --project . --output pipsutra-report.json
```

Run offline source checks and inventory without contacting OSV:

```bash
pipsutra scan --project . --no-osv --output pipsutra-report.json
```

Run only dependency inventory:

```bash
pipsutra inventory --project . --output pipsutra-inventory.json
```

Inspect a different installed environment:

```bash
pipsutra scan --project . --environment /path/to/.venv
```

Set the OSV request timeout (seconds):

```bash
pipsutra scan --project . --timeout 20
```

Use the scanner as a CI gate (the command exits with status `1` when a finding
meets or exceeds the selected severity):

```bash
pipsutra scan --project . --fail-on high
```

The default is `--fail-on none`, which reports findings without failing the
process. An `UNKNOWN` severity does not meet a severity threshold.

## How dependency discovery works

- Declared main dependencies are read from `requirements.txt` and
  `[project].dependencies` in `pyproject.toml`.
- Optional dependency groups in `[project.optional-dependencies]` are recorded
  but are not treated as selected installation roots.
- Installed distributions are read from metadata in the selected environment;
  PipSutra does not import or execute installed package modules.
- Edges are inferred from installed `Requires-Dist` metadata when the child is
  installed and its environment marker evaluates true in the running Python
  environment.
- Vulnerability checks cover installed packages reachable from declared main
  dependencies. Unlinked packages in the environment are not sent to OSV.

This is not a full dependency resolver. v0.1.0 does not resolve version
constraints, validate that installed versions satisfy declared specifiers, or
support lockfiles, nested requirements, constraints files, editable installs,
VCS requirements, line continuations, or selecting optional groups. Common pip
index/installer options and inline `--hash` tokens are ignored because they do
not declare dependencies. Marker evaluation reflects the current
interpreter/platform only. Dependency graph accuracy therefore depends
on the metadata available in the installed environment.

## Privacy and network behavior

- Inventory and AST checks run locally.
- AST analysis reads `.py` files under the project and skips common generated or
  environment directories such as `.git`, `.venv`, `venv`, `site-packages`, and
  `__pycache__`.
- The OSV check sends package names, versions, and the PyPI ecosystem identifier
  to the public OSV API. It does not upload project source files.
- Use `--no-osv` to disable network vulnerability checks.
- PipSutra does not install packages or execute package code.

## Understanding the risk score

The score adds fixed weights for detected findings and caps the result at 100:

| Finding severity | Weight |
|---|---:|
| LOW | 5 |
| MEDIUM | 15 |
| HIGH | 25 |
| CRITICAL | 35 |
| UNKNOWN | 8 |

Score bands are 0–19 LOW, 20–44 MEDIUM, 45–74 HIGH, and 75–100 CRITICAL.
Incomplete checks force the overall level to UNKNOWN. The score is a
prioritization heuristic, not a calibrated probability, exploitability
assessment, or certification. The JSON report includes the underlying findings
so teams can review evidence rather than relying on the aggregate score. The
versioned report schema is published at
[`docs/schemas/scan-report.schema.json`](docs/schemas/scan-report.schema.json).

An OSV request failure is reported separately; it must not be interpreted as a
clean vulnerability result. An empty result means OSV returned no matching
records for the queried package versions at scan time, not that the packages
are guaranteed safe.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
ruff format --check .
mypy src/pipsutra
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Releasing

See [docs/RELEASING.md](docs/RELEASING.md) for the release workflow and the
required PyPI Trusted Publishing setup.

## Security reporting

Please see [SECURITY.md](SECURITY.md). Do not use PipSutra as the sole control
for production security decisions.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Project status

Alpha / research-oriented development. Interfaces and report schemas may
change before v1.0.0. See [the architecture](docs/ARCHITECTURE.md) and
[research methodology](docs/RESEARCH_METHODOLOGY.md) for current design and
limitations.
