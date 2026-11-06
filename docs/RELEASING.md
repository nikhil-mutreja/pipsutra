# Releasing PipSutra

## Package identity and name availability

The project currently uses the working brand and proposed PyPI distribution
name `PipSutra` / `pipsutra`. A public lookup on 6 November 2026 found no exact
PyPI project page for `pipsutra` (the exact project URL returned HTTP 404).
This is only a point-in-time availability check, not a reservation or
trademark clearance. Recheck immediately before publishing and investigate
relevant trademark databases before treating the name as legally cleared.

## One-time setup

1. Create the GitHub repository and push the reviewed source.
2. Recheck the distribution name and create/configure its PyPI project.
3. In PyPI, add a Trusted Publisher for GitHub Actions using the exact GitHub
   owner, repository, workflow filename `.github/workflows/release.yml`, and
   environment name `pypi`.
4. In GitHub, create an environment named `pypi`. Add approval protection if
   desired. Do not add a long-lived PyPI API token to repository secrets.
5. Verify that CI passes on all supported Python and operating-system matrix
   entries.

## Release procedure

1. Update the version in `pyproject.toml` and `src/pipsutra/_version.py` in the
   same change.
2. Update release notes and confirm the report schema/CLI behavior.
3. Run tests, lint, formatting, and type checks locally.
4. Build and inspect distributions:

   ```bash
   python -m pip install --upgrade build twine
   python -m build
   python -m twine check dist/*
   ```

5. Test installation from TestPyPI before the production release.
6. Merge the reviewed release commit, create a GitHub Release with tag
   `vX.Y.Z`, and publish it. The release workflow builds the distributions in
   a separate job and publishes them through PyPI Trusted Publishing.
7. Verify the published files, checksums, attestations, and installation from
   a clean virtual environment.

The PyPA publishing action can generate and upload PEP 740 attestations during
Trusted Publishing. This attests to the publishing workflow identity; it is not
a guarantee that the source code or dependencies are free of vulnerabilities.

## Do not release if

- the PyPI distribution name is unresolved;
- CI or package build fails;
- the release cannot be installed in a clean environment;
- a critical security or data-loss issue remains open;
- README claims exceed the tested behavior.
