//! The JSON messages of OID4VP and SIOPv2: Authorization Request parameters, Client Metadata, the
//! VP Token and its decoded form, the Authorization Response parameters, ID Token claim requests.
//! Arbitrary input never panics, and a message that parses serializes to one that parses to the
//! same value.
#![no_main]

use std::fmt::Debug;

use libfuzzer_sys::fuzz_target;
use oid4vc_core::client_metadata::ClientMetadataResource;
use oid4vp::authorization_request::{AuthorizationRequestParameters, ClientMetadataParameters};
use oid4vp::oid4vp::AuthorizationResponseParameters;
use oid4vp::token::vp_token_validator::DecodedVpToken;
use oid4vp::VpToken;
use serde::de::DeserializeOwned;
use serde::Serialize;
use siopv2::authorization_request::AuthorizationRequestParameters as SiopRequestParameters;
use siopv2::siopv2::AuthorizationResponseParameters as SiopResponseParameters;
use siopv2::{ClaimRequests, StandardClaimsRequests, StandardClaimsValues};

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + Debug>(data: &[u8]) -> Option<T> {
    let parsed: T = serde_json::from_slice(data).ok()?;
    let json = serde_json::to_value(&parsed).expect("a parsed message serializes");
    let again: T = serde_json::from_value(json).expect("a serialized message parses");
    assert_eq!(again, parsed);
    Some(parsed)
}

fuzz_target!(|data: &[u8]| {
    if let Some(parameters) = round_trip::<AuthorizationRequestParameters>(data) {
        let _ = parameters.dcql_query.validate_all();
    }
    round_trip::<ClientMetadataParameters>(data);
    round_trip::<ClientMetadataResource<ClientMetadataParameters>>(data);
    if let Some(token) = round_trip::<VpToken>(data) {
        for presentations in token.presentations().values() {
            for presentation in presentations.iter() {
                let _ = presentation.as_str();
                let _ = presentation.as_object();
            }
        }
    }
    round_trip::<DecodedVpToken>(data);
    round_trip::<AuthorizationResponseParameters>(data);

    if let Some(parameters) = round_trip::<SiopRequestParameters>(data) {
        let _ = parameters.is_cross_device_request();
        let _ = parameters.subject_syntax_types_supported();
        let _ = parameters.id_token_request_claims();
    }
    round_trip::<SiopResponseParameters>(data);
    round_trip::<ClaimRequests>(data);
    round_trip::<StandardClaimsRequests>(data);
    round_trip::<StandardClaimsValues>(data);
});
