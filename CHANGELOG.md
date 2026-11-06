# Changelog

All notable changes to PipSutra are documented here.

## [0.1.0] - 2026-12-01

### Added

- Read declared dependencies from `requirements.txt` and PEP 621 dependency
  fields in `pyproject.toml`.
- Inspect installed distribution metadata without importing package modules.
- Infer direct/transitive dependency reachability from installed metadata.
- Query exact installed PyPI package versions through the OSV batch API.
- Four explainable Python AST rules: `DG-PY-001` (`eval`/`exec`),
  `DG-PY-002` (`os.system`), `DG-PY-003` (subprocess `shell=True`),
  `DG-PY-004` (`pickle.loads`).
- Versioned JSON scan reports and terminal summaries.
- Severity-based CI exit gating with `--fail-on`.
- Cross-platform CI (Linux, Windows, macOS; Python 3.11–3.13).
- PyPI Trusted Publishing release workflow.
- Developer attribution: Nikhil Mutreja.
- Apache-2.0 license.

### Limitations

- No lockfile-native dependency resolution, package provenance verification,
  dynamic sandboxing, malware verdicts, or automatic remediation.
- Vulnerability coverage depends on OSV availability and data quality.
- Static rules are intentionally limited and can produce false positives and
  false negatives.
- The aggregate risk score is a heuristic, not a calibrated probability or
  safety certification.
- Marker evaluation reflects the running interpreter/platform only.
