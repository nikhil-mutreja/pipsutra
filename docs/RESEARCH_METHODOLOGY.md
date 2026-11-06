# Research methodology

## Research direction

**An Explainable Multi-Signal Framework for Risk Assessment of Python Software
Dependencies.**

The research contribution should be evaluated as an integration and
measurement question, not as a claim that dependency graphs, vulnerability
feeds, or AST analysis are individually novel.

## Current v0.1.0 signals

- Dependency context: direct/transitive reachability inferred from installed
  distribution metadata.
- Known vulnerability records: exact package/version lookups against OSV.
- Source-pattern evidence: four deterministic AST rules with file and line
  locations.

The score is a transparent heuristic. It is not trained, calibrated, or
validated as a probability. Do not describe it as one.

## Evaluation plan before a research claim

1. Build a documented, versioned fixture corpus with benign and intentionally
   vulnerable/suspicious examples.
2. Label each fixture and record the source and date of each vulnerability
   ground-truth item.
3. Measure precision, recall, false-positive rate, false-negative rate, and
   scan failures separately for each signal.
4. Compare vulnerability coverage with an established tool such as
   `pip-audit`, using the same environment snapshot and date where possible.
5. Measure runtime and memory on declared hardware/software; repeat runs.
6. Publish limitations, excluded cases, and raw machine-readable results.

No performance or detection-rate claim should be made until the experiment has
actually been run. Example targets are not results.

## Reproducibility fields

Record PipSutra version, Python version, OS/platform, manifest files, selected
environment, scan timestamp, OSV response status, fixture commit/hash, and
command-line options for each benchmark run.
