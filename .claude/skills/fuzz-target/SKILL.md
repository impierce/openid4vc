---
name: fuzz-target
description: Add or extend a cargo-fuzz target in fuzz/ for a parser or wire type of this workspace, seed it from the specification examples, run it, and triage a crash. Use when adding a new request, response or metadata type, when a parser changes, when asked to "fuzz" something, or when the Fuzz workflow is red.
---

# Fuzz targets

`fuzz/` is a Cargo workspace of its own (`cargo-fuzz`, nightly, libFuzzer). Each target in
`fuzz/fuzz_targets/` feeds arbitrary bytes to one surface and asserts two properties for every
input: nothing panics, and whatever parses survives a round trip through its serialization.
`fuzz/README.md` is the reference (targets, seeds, corpus, CI); this skill is the procedure.

## Which target

| Surface                                                                  | Target                  |
| ------------------------------------------------------------------------ | ----------------------- |
| `openid-credential-offer://` URLs, `CredentialOfferParameters`           | `credential_offer`      |
| `<scheme>://?...` authorization requests (generic, OID4VP, SIOPv2, by reference, by value), `ClientId` | `authorization_request` |
| `DcqlQuery`, its evaluation against decoded presentations, `ClaimPathPointer` | `dcql_query`        |
| OID4VCI JSON messages (metadata, token, credential, nonce, notification) | `issuance_messages`     |
| OID4VP and SIOPv2 JSON messages (request parameters, client metadata, VP token, claims) | `presentation_messages` |
| Compact JWTs and SD-JWTs before signature check, Subject Syntax Types, DID methods | `jwt` |
| `VpTokenValidator` (signature, holder binding, status, DCQL evaluation of the decoded credentials) | `vp_token_validation` |

A new JSON type joins `issuance_messages` or `presentation_messages` with one `round_trip::<T>(data)`
line. A new input format (a new URL scheme, a compact serialization, a new query language) gets a
target of its own: a file in `fuzz_targets/`, a `[[bin]]` in `fuzz/Cargo.toml` with `test`, `doc`
and `bench` off, and a doc comment at the top stating the property. The Fuzz workflow discovers
targets from the manifest; nothing else to register.

## Writing the assertion

- Parse failures are fine (`let Ok(x) = parse(data) else { return }`); panics are not.
- After a successful parse, serialize and parse again, then `assert_eq!`. Compare the typed values,
  not the JSON text: serialization legitimately drops unknown fields and normalizes URLs.
- Call the methods a consumer would call on the parsed value (`validate_all`, `evaluate_*`,
  getters); their result is irrelevant, their not panicking is the point.
- When a round trip is known not to hold (a lossy `Display`, a lenient alias on input), narrow the
  assertion and say why in a comment next to it, citing the specification. Do not weaken the
  assertion silently.

## Seeds

`fuzz/seeds/<target>/` holds one file per specification example, named after its source
(`oid4vp-dcql-simple.json`, `oid4vci-credential-offer-by-reference-url.txt`), copied from
`*/tests/examples/` or built from them (URL forms are the example JSON `urlencode`d). A new example
added under `tests/examples` for a unit test also gets a seed. Hand-made seeds are allowed for
shapes the specifications have no example of; name them after what they hold.

## Running

```sh
cargo +nightly fuzz list
fuzz/run.sh <target> 60                     # over the corpus and the seeds, one minute
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<sha1>   # replay
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<sha1>  # minimize
```

`run.sh` passes the corpus directory first and the seeds second; run `cargo fuzz run` by hand the
same way or the seeds are ignored. `fuzz/corpus/` and `fuzz/artifacts/` are generated and ignored by
git.

## When a target finds something

1. Replay and minimize the input.
2. Decide: a panic in `*/src` is a bug (fix it, return an error instead, add the input as a regular
   test in the crate); a wrong assumption in the target is narrowed with a comment.
3. A fix to the parser goes in the same pull request as the regression test, titled
   `fix(<crate>): ...`; the target's assertion stays.
4. Never delete a seed or a `[[bin]]` to get the workflow green.
