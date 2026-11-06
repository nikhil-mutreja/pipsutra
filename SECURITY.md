# Security Policy

## Reporting a vulnerability

Please do not disclose an unpatched vulnerability in a public issue. Contact
the project maintainers privately through the security contact configured in
the repository's GitHub Security Advisories feature.

If no private reporting channel is configured yet, do not assume this file
creates a monitored inbox. The maintainers must configure and test the channel
before public release.

## Scope

Reports may concern PipSutra code, its release process, or unsafe handling of
untrusted project metadata. Include reproduction steps and impact where safe.

## Scanner limitations

PipSutra v0.1.0 performs dependency inventory, OSV lookups, and a limited set
of Python AST pattern checks. It does not determine whether a package is
malicious or vulnerability-free. Its checks can miss issues and can produce
false positives. Do not use it as the sole security control.
