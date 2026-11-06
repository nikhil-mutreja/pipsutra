# Changelog

All notable changes to PipSutra are documented here.

## [0.1.0] - 2026-12-01

- Initial planned public release.
- Project renamed from DepGuard to PipSutra before publication.
- Developer attribution: Nikhil Mutreja.

## [0.1.0] - Unreleased

### Added

- Read declared dependencies from `requirements.txt` and PEP 621 dependency
  fields in `pyproject.toml`.
- Inspect installed distribution metadata without importing package modules.
- Infer direct/transitive dependency reachability from installed metadata.
- Query exact installed PyPI package versions through the OSV batch API.
- Add four explainable Python AST rules for dynamic execution, shell command
  execution, and unsafe pickle deserialization.
- Produce versioned JSON scan reports and terminal summaries.
- Add severity-based CI exit gating with `--fail-on`.
- Add tests, cross-platform CI configuration, security policy, and a PyPI
  Trusted Publishing release workflow.

### Limitations

- No lockfile-native dependency resolution, package provenance verification,
  dynamic sandboxing, malware verdicts, or automatic remediation.
- Vulnerability coverage depends on OSV availability and data quality.
- Static rules are intentionally limited and can produce false positives and
  false negatives.
- The aggregate risk score is a heuristic, not a calibrated probability.
- The PyPI distribution name must be finalized before publishing; see
  [docs/RELEASING.md](docs/RELEASING.md).
