//! Authorization Requests in their URL form, `<scheme>://?<query>` (OID4VP "Authorization Request",
//! SIOPv2 "Self-Issued OpenID Provider Authorization Request", OAuth 2.0 requests by reference and
//! by value), and OID4VP Client Identifiers. Nothing panics; a parsed request prints to a URL that
//! parses to the same request, and a parsed Client Identifier prints to the same identifier.
#![no_main]

use std::fmt::Debug;
use std::str::FromStr as _;

use libfuzzer_sys::fuzz_target;
use oid4vc_core::authorization_request::{AuthorizationRequest, Body, ByReference, ByValue, Object};
use oid4vc_core::openid4vc_extension::Generic;
use oid4vp::authorization_request::ClientId;
use oid4vp::oid4vp::OID4VP;
use serde::de::DeserializeOwned;
use siopv2::siopv2::SIOPv2;

/// A parsed request prints to a URL that parses to the same request.
fn round_trip<B: Body + DeserializeOwned + PartialEq + Debug>(input: &str) -> Option<AuthorizationRequest<B>> {
    let request = AuthorizationRequest::<B>::from_str(input).ok()?;
    let printed = request.to_string();
    match AuthorizationRequest::<B>::from_str(&printed) {
        Ok(again) => assert_eq!(
            again, request,
            "a printed request parses to the same request: {printed}"
        ),
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
        let again = ClientId::from_str(&client_id.to_string()).expect("a printed client identifier parses");
        assert_eq!(again, client_id);
    }
});
