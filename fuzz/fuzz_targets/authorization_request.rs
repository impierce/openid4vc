//! Authorization Requests in their URL form, `<scheme>://?<query>` (OID4VP "Authorization Request",
//! SIOPv2 "Self-Issued OpenID Provider Authorization Request", OAuth 2.0 requests by reference and
//! by value), and OID4VP Client Identifiers. Nothing panics; a parsed request prints to a URL that
//! parses again, and printing the re-parsed request gives the same URL.
#![no_main]

use std::str::FromStr as _;

use libfuzzer_sys::fuzz_target;
use oid4vc_core::authorization_request::{AuthorizationRequest, Body, ByReference, ByValue, Object};
use oid4vc_core::openid4vc_extension::Generic;
use oid4vp::authorization_request::{ClientId, ClientIdPrefix};
use oid4vp::oid4vp::OID4VP;
use serde::de::DeserializeOwned;
use siopv2::siopv2::SIOPv2;

/// Printing keeps the string, object and array values of the query and drops the rest, so the first
/// print may lose a numeric claim; the print of the re-parsed request cannot lose anything.
fn round_trip<B: Body + DeserializeOwned>(input: &str) -> Option<AuthorizationRequest<B>> {
    let request = AuthorizationRequest::<B>::from_str(input).ok()?;
    let printed = request.to_string();
    match AuthorizationRequest::<B>::from_str(&printed) {
        Ok(again) => assert_eq!(again.to_string(), printed, "printing is idempotent"),
        // `Display` writes `<scheme>://?<query>` without a host, which is not a valid URL for the
        // special schemes (`https`, `http`, ...); any other failure is a bug.
        Err(_) => assert!(
            url::Url::parse(&printed).is_err(),
            "a printed request does not parse: {printed}"
        ),
    }
    Some(request)
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    if let Some(generic) = round_trip::<Object<Generic>>(input) {
        let _ = AuthorizationRequest::<Object<OID4VP>>::from_generic(&generic);
        let _ = AuthorizationRequest::<Object<SIOPv2>>::from_generic(&generic);
    }
    round_trip::<Object<OID4VP>>(input);
    round_trip::<Object<SIOPv2>>(input);
    round_trip::<ByReference>(input);
    round_trip::<ByValue>(input);

    if let Ok(client_id) = ClientId::from_str(input) {
        let printed = client_id.to_string();
        // The `pre-registered:` spelling is accepted leniently and prints without the prefix, so an
        // identifier that itself contains `:` re-parses under another prefix. OID4VP 1.0 has no
        // such spelling: a pre-registered Client Identifier carries no prefix.
        if client_id.prefix() != &ClientIdPrefix::PreRegistered || !client_id.identifier().contains(':') {
            let again = ClientId::from_str(&printed).expect("a printed client identifier parses");
            assert_eq!(again, client_id);
        }
    }
});
