# Architecture

## v0.1.0 pipeline

1. **Manifest discovery** parses supported requirement declarations.
2. **Environment inspection** reads installed distribution metadata through
   `importlib.metadata`; package modules are not imported.
3. **Graph construction** uses installed `Requires-Dist` metadata and current
   environment marker evaluation.
4. **Vulnerability intelligence** sends exact package/version queries for
   direct and graph-reachable dependencies to OSV's batch API.
5. **Static source checks** parse project Python files with `ast` and apply the
   public rules documented in the README.
6. **Risk summary** aggregates findings using fixed, inspectable weights.
7. **Reporting** emits typed JSON and a concise terminal summary.

## Trust boundaries

- Project manifests and source files are untrusted input. Parsing errors are
  surfaced; source files are never executed.
- Installed package metadata is treated as descriptive input, not proof of
  package integrity.
- OSV is an external service. Network errors are recorded and must not be
  interpreted as a clean result.
- The heuristic score is for triage only and must not replace human review.

## Deliberate v0.1.0 limitations

No full resolver, lockfile parser, cryptographic PyPI attestation verification,
malware classification, dynamic sandbox, taint analysis, interprocedural AST
analysis, or automatic remediation. These require separate designs and
validation before being advertised as security controls.

## Release checklist (before publishing v0.1.0)

- [ ] Run the test suite on Python 3.11, 3.12, and 3.13 on Linux, Windows, and
  macOS where practical.
- [ ] Run lint, formatting, and type checks in a clean environment.
- [ ] Verify wheel and source distribution contents.
- [ ] Test installation from TestPyPI before PyPI publication.
- [ ] Configure and test the private security reporting channel.
- [ ] Pin release tag and publish checksums and build provenance for PipSutra's
  own artifacts.
- [ ] Publish a known-limitations page and benchmark fixture corpus.
- [ ] Review all examples and ensure no result implies that zero findings means
  the project is safe.
