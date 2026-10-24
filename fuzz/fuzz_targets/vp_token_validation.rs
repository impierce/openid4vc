//! `VpTokenValidator::validate_vp_token` over an arbitrary presentation (OID4VP "VP Token"): the
//! first byte picks the DCQL query it is validated against, one credential query of format
//! `jwt_vc_json`, `dc+sd-jwt` or `vc+sd-jwt`, with or without cryptographic holder binding; the rest
//! is the presentation. Nothing panics, and a VP token that validates decodes to one credential.
//! Keys resolve over `did:key` only, so a presentation that validates comes from a seed.
#![no_main]

use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use futures::executor::block_on;
use identity_kit::methods::DidKey;
use identity_kit::resolver::Resolver;
use identity_kit::vc::validation::{CredentialStatus, StatusCheck, StatusError};
use libfuzzer_sys::fuzz_target;
use oid4vp::dcql::dcql_query::DcqlQuery;
use oid4vp::token::vp_token_validator::VpTokenValidator;
use oid4vp::VpToken;
use serde_json::json;

/// The `client_id` the seeds' presentations are bound to.
const CLIENT_ID: &str = "decentralized_identifier:did:key:z6MkeupePVKikLv4KXE99oAvQbgAR7qXq3AGUtsSeoqZgFBV";

/// A status check that finds every credential valid, so status lists are never fetched.
struct Valid;

#[async_trait::async_trait]
impl StatusCheck for Valid {
    async fn check(&self, _: CredentialStatus<'_>, _: DateTime<Utc>) -> Result<(), StatusError> {
        Ok(())
    }
}

static VALIDATOR: LazyLock<VpTokenValidator<Resolver>> =
    LazyLock::new(|| VpTokenValidator::new(Resolver::builder().with(DidKey::default()).build(), Valid));

/// The format, its `meta`, the claim asked for and the nonce of the seed of that format.
const FORMATS: [(&str, &str, &[&str], &str); 3] = [
    (
        "jwt_vc_json",
        "type_values",
        &["credentialSubject", "first_name"],
        "be1a1b20084f6566033de7bc2f90b837722feab4ab6af71cecb89ff42745abcd",
    ),
    (
        "dc+sd-jwt",
        "vct_values",
        &["first_name"],
        "1c2c6864a3f4e335712bb7890249d3c46e177dd62e3e93bc3a4d08acde7d4ab4",
    ),
    (
        "vc+sd-jwt",
        "type_values",
        &["credentialSubject", "first_name"],
        "8df91a4a19cb1babda8bb599abe52caeae5aa8819f38d762d13446add7bd09f4",
    ),
];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, presentation)) = data.split_first() else {
        return;
    };
    let Ok(presentation) = std::str::from_utf8(presentation) else {
        return;
    };
    // `'0'` to `'5'` in the seeds: the three formats with holder binding, then without.
    let index = usize::from(selector) % 6;
    let (format, meta, path, nonce) = FORMATS[index % 3];
    let meta_values = match meta {
        "vct_values" => json!(["http://localhost:3033/vct/U0QtSldUIFZD/0"]),
        _ => json!([["VerifiableCredential"]]),
    };
    let dcql_query: DcqlQuery = serde_json::from_value(json!({
        "credentials": [{
            "id": "query",
            "format": format,
            "meta": {meta: meta_values},
            "require_cryptographic_holder_binding": index < 3,
            "claims": [{"path": path}],
        }],
    }))
    .expect("the DCQL query is valid");
    let vp_token: VpToken = serde_json::from_value(json!({"query": [presentation]})).expect("the VP token is valid");

    if let Ok(decoded) = block_on(VALIDATOR.validate_vp_token(&dcql_query, &vp_token, CLIENT_ID, nonce)) {
        assert_eq!(decoded.decoded_presentations().len(), 1, "one credential query");
    }
});
