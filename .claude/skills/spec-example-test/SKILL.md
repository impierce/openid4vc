---
name: spec-example-test
description: Add a test that checks a wire type against an example from an OpenID4VC specification (OID4VCI, OID4VP, SIOPv2). Use when adding or changing a request, response or metadata type, when a spec example is cited in an issue, or when asked to "test against the spec".
---

# Specification example tests

The test oracle of this workspace is the specification text, never another implementation's
output. Every wire type should round-trip the examples the specification gives for it.

## Where examples live

| Crate     | Directory                          | Content                                                                  |
| --------- | ---------------------------------- | ------------------------------------------------------------------------ |
| `oid4vci` | `oid4vci/tests/examples/`          | credential offers, authorization details, issuer metadata, per format    |
| `oid4vp`  | `oid4vp/tests/examples/`           | `query_lang/` (DCQL), `request/`, `client_metadata/`, `credentials/`     |
| `siopv2`  | inline in `siopv2/src/*/tests`     | authorization requests and ID tokens                                     |
| flows     | `oid4vc-manager/tests/common/`     | credential configurations and credentials used by the end-to-end tests   |

One JSON file per example, named after what it holds: `credential_offer_pre-authz_code.json`,
`authorization_details_sd_jwt_vc.json`, `query_lang/credentials_alternatives.json`. Copy the
example verbatim from the specification; if it has to be adapted (a placeholder, an elided
field), say so in a comment in the test, not by changing the JSON silently.

## The test pattern

The existing tests deserialize the example into the typed struct, assert the fields that matter,
and serialize it back to the same JSON. Follow that shape:

```rust
#[test]
fn test_credential_offer_pre_authorized_code() {
    // OID4VCI 1.0, Credential Offer Parameters: example with a pre-authorized code grant.
    let json = include_str!("../tests/examples/credential_offer_pre-authz_code.json");
    let offer: CredentialOfferParameters = serde_json::from_str(json).unwrap();

    assert_eq!(
        offer.grants.as_ref().unwrap().pre_authorized_code.as_ref().unwrap().pre_authorized_code,
        "adhjhdjajkdkhjhdj"
    );

    // Round trip: the type must not lose or invent fields.
    let expected: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(serde_json::to_value(&offer).unwrap(), expected);
}
```

For `oid4vci` and `oid4vp` there are table-driven tests over a whole directory
(`test_oid4vci_examples`, `test_oid4vp_example_*`); add a new file there when a directory already
has one, and add an explicit test only for assertions the table cannot express.

## Cite the specification

Name the spec and the section in a comment at the top of the test, and in the doc comment of the
type when the type is new. The versions this workspace tracks are listed in `docs/FEATURES.md`:
OID4VCI 1.0 (final), OID4VP 1.0 (final), SIOPv2 draft 13. When a type exists only in a draft (for
example Interactive Authorization), cite the draft.

## Query strings and URLs

Authorization requests and credential offers travel as query strings. `oid4vc-core` has
`to_form_urlencoded_string` / `from_form_urlencoded_string` and the types implement `FromStr` and
`Display`; test both directions when the example is a URL rather than JSON (see
`test_serde_roundtrip_string` in `oid4vc-core` and `test_credential_offer_serde` in `oid4vci`).

## Done when

- The JSON file is committed under the crate's examples directory with a descriptive name.
- The test cites the spec section and round-trips the example.
- `docs/FEATURES.md` has the row flipped to ✅ if the test proves a feature.
