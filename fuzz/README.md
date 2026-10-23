# Fuzzing

The parsers of this workspace are fuzzed with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz), the Cargo front end for LLVM's [libFuzzer](https://llvm.org/docs/LibFuzzer.html).
Each target in this directory feeds arbitrary bytes to one surface of the crates and asserts a property that must hold for every input: nothing panics, and whatever parses survives a round trip through its serialization.
libFuzzer mutates the inputs, keeps every input that reaches code the previous ones did not, and stops at the first panic, crash or timeout.
It runs on nightly, with AddressSanitizer, which is why this directory is a Cargo workspace of its own and `exclude`d from the library workspace.

## Targets

One file per target in [`fuzz_targets/`](fuzz_targets/); the doc comment at the top of each states the property it asserts.

| Target                  | Surface                                                                                                                     | Input                                                            |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `credential_offer`      | `CredentialOffer` (`openid-credential-offer://` URL, by value and by reference), `CredentialOfferParameters`                   | a URL or a JSON object                                           |
| `authorization_request` | `AuthorizationRequest<Object<Generic \| OID4VP \| SIOPv2>>`, `AuthorizationRequest<ByReference \| ByValue>`, `ClientId`     | a `<scheme>://?<query>` URL or a Client Identifier               |
| `dcql_query`            | `DcqlQuery` parsing, validation and evaluation against decoded presentations, `ClaimPathPointer` selection                  | a DCQL query; `{dcql_query, presentations}`; `{path, value}`     |
| `issuance_messages`     | OID4VCI: issuer and authorization server metadata, credential configurations, authorization details, token request (JSON and form-encoded) and response, credential request and response, nonce and notification | a JSON document or a form-encoded token request |
| `presentation_messages` | OID4VP and SIOPv2: request parameters, client metadata, VP token and decoded VP token, response parameters, claim requests   | a JSON document                                                  |
| `jwt`                   | Compact JWTs and SD-JWTs before signature check (`extract_header`, `extract_normalized_did_kid_from_jwt`, unverified claims), `SubjectSyntaxType`, `DidMethod` | a JWT, an SD-JWT or a Subject Syntax Type |

## Layout

```
fuzz/
├── Cargo.toml          # one [[bin]] per target; the Fuzz workflow discovers the targets here
├── fuzz_targets/       # the targets
├── seeds/<target>/     # committed starting inputs, one file per specification example
├── corpus/<target>/    # what the fuzzer discovers; generated, not committed
├── artifacts/<target>/ # the input of a failing run; generated, not committed
└── run.sh              # runs one target over its corpus and seeds
```

### Seeds

libFuzzer starts from whatever inputs it is given and mutates from there, so a seed that already parses puts it deep into the code from the first run instead of leaving it to guess the shape of a DCQL query or a credential offer URL byte by byte.
The seeds in `seeds/<target>/` are the specification examples the unit tests run against (`oid4vci/tests/examples`, `oid4vp/tests/examples`), the URL forms built from them, and a few hand-made messages for the types the specifications give no standalone example of.
Every file is named after what it holds, so it can be read and reviewed: `oid4vp-dcql-complex-mdoc.json` is the complex mdoc example of the OID4VP DCQL section, `oid4vci-credential-offer-by-reference-url.txt` is that credential offer as an `openid-credential-offer://` URL, `evaluation-credential-set-alternatives.json` is a query with credential sets next to the presentations it is evaluated against.
The names are for people; libFuzzer reads only the bytes.

### Corpus and artifacts

`corpus/<target>/` is where libFuzzer writes every input that reached new coverage.
Files there are named by the SHA-1 of their content, the libFuzzer convention, and they are mutated bytes nobody needs to read; the directory is in `.gitignore`.
In CI the corpus is cached per target between runs ([`actions/cache`](../.github/workflows/fuzz.yml)), so each run continues from the coverage of the previous one; locally it accumulates in your checkout.
Deleting it costs nothing but the time to rediscover it.

`artifacts/<target>/` holds the input of a failing run as `crash-<sha1>`, `timeout-<sha1>` or `oom-<sha1>`; the file is also what the workflow uploads when a job fails.

## Running locally

```sh
cargo install --locked cargo-fuzz
rustup toolchain install nightly

cargo +nightly fuzz list                        # the targets
fuzz/run.sh dcql_query 600                      # one target, ten minutes, over its corpus and seeds
cargo +nightly fuzz run dcql_query fuzz/artifacts/dcql_query/crash-…   # replay a failing input
cargo +nightly fuzz tmin dcql_query fuzz/artifacts/dcql_query/crash-…  # shrink it to the smallest failing input
cargo +nightly fuzz coverage dcql_query fuzz/corpus/dcql_query fuzz/seeds/dcql_query   # coverage of the corpus
```

`run.sh` passes the corpus directory first and the seeds second, which is how libFuzzer tells where to write (the first) from what to read (the rest); run `cargo fuzz run` by hand the same way, or the seeds are left out.
The first build compiles the whole dependency graph, including the `identity_*` git dependencies, with sanitizers; allow several minutes.

## In CI

The [Fuzz workflow](../.github/workflows/fuzz.yml) reads the targets from `Cargo.toml` and runs each one in its own job, for a minute on pull requests that touch a crate's `src/`, a manifest or `fuzz/`, and for ten minutes nightly, restoring and saving the corpus cache around the run.
A failing job uploads `artifacts/<target>/` for replay.

## When a target finds something

A crash is a bug in a crate, or a property the target states too strongly; the input decides which.

- A bug: fix it in the crate's `src/`, add the input's behaviour as a regular test against the specification it violates, keep the target's assertion.
- A wrong assumption in the target (a lossy `Display`, an alias the parser accepts leniently): narrow the assertion and say why in a comment next to it.

## Adding a target or a seed

A target is a file in `fuzz_targets/` and a `[[bin]]` entry in `Cargo.toml` with `test`, `doc` and `bench` off; the workflow picks it up from the manifest.
State the property in the doc comment, and seed it from the specifications' examples under `seeds/<target>/`, one example per file, named after its source.
A new JSON wire type usually needs no new target: one `round_trip::<T>(data)` line in `issuance_messages` or `presentation_messages` and a seed.
