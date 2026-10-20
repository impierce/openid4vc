# Security Policy

## Supported versions

Until the crates are released from this repository's release process (see
[`docs/PLAN.md`](docs/PLAN.md)), security fixes land on the default branch. Once releases exist,
only the latest released version of each crate receives security fixes until 1.0.

The `0.1.0` versions of `oid4vci`, `oid4vp`, `siopv2` and `oid4vc` published to crates.io in June
2023 are not supported.

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public issues, discussions or pull requests.

Instead, report them privately through [GitHub's private vulnerability reporting](https://github.com/impierce/openid4vc/security/advisories/new).

Please include as much of the following as you can:

- The affected crate(s) and version or commit, and the enabled crate features if relevant
- A description of the vulnerability and its impact
- Steps to reproduce, ideally a minimal proof of concept

## What happens next

We will acknowledge your report, investigate it and keep you updated on our progress in the advisory.
Once a fix is released, we publish a GitHub Security Advisory and request a [RustSec](https://rustsec.org/) advisory, so that users of `cargo audit` and `cargo deny` are notified.
Unless you prefer otherwise, we credit you in the advisory.
