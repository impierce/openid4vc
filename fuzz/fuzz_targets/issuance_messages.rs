//! The JSON messages of OID4VCI: Credential Issuer and Authorization Server metadata, Credential
//! Configurations, Authorization Details, Token Request (also form-encoded) and Response, Credential
//! Request and Response, Nonce Response, Notification Request. Arbitrary input never panics, and a
//! message that parses serializes to one that parses to the same value.
#![no_main]

use std::fmt::Debug;

use libfuzzer_sys::fuzz_target;
use oid4vc_core::utils::form_urlencoded::{from_form_urlencoded_string, to_form_urlencoded_string};
use oid4vci::authorization_details::AuthorizationDetailsObject;
use oid4vci::credential_format_profiles::CredentialFormats;
use oid4vci::credential_issuer::authorization_server_metadata::AuthorizationServerMetadata;
use oid4vci::credential_issuer::credential_configurations_supported::CredentialConfigurationsSupportedObject;
use oid4vci::credential_issuer::credential_issuer_metadata::CredentialIssuerMetadata;
use oid4vci::credential_request::CredentialRequest;
use oid4vci::credential_response::CredentialResponse;
use oid4vci::nonce_response::NonceResponse;
use oid4vci::notification_request::NotificationRequest;
use oid4vci::token_request::TokenRequest;
use oid4vci::token_response::TokenResponse;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + Debug>(data: &[u8]) -> Option<T> {
    let parsed: T = serde_json::from_slice(data).ok()?;
    let json = serde_json::to_value(&parsed).expect("a parsed message serializes");
    let again: T = serde_json::from_value(json).expect("a serialized message parses");
    assert_eq!(again, parsed);
    Some(parsed)
}

fuzz_target!(|data: &[u8]| {
    if let Some(metadata) = round_trip::<CredentialIssuerMetadata>(data) {
        for configuration in metadata.credential_configurations_supported.values() {
            let _ = configuration.credential_format.format();
        }
    }
    round_trip::<AuthorizationServerMetadata>(data);
    round_trip::<CredentialConfigurationsSupportedObject>(data);
    round_trip::<CredentialFormats>(data);
    round_trip::<Vec<AuthorizationDetailsObject>>(data);
    round_trip::<AuthorizationDetailsObject>(data);
    round_trip::<TokenRequest>(data);
    round_trip::<TokenResponse>(data);
    round_trip::<CredentialRequest>(data);
    round_trip::<CredentialResponse>(data);
    round_trip::<NotificationRequest>(data);

    // `NonceResponse` has no `PartialEq`; compare the JSON.
    if let Ok(nonce) = serde_json::from_slice::<NonceResponse>(data) {
        let json = serde_json::to_value(&nonce).expect("a nonce response serializes");
        let again: NonceResponse = serde_json::from_value(json.clone()).expect("a serialized nonce response parses");
        assert_eq!(serde_json::to_value(&again).expect("a nonce response serializes"), json);
    }

    // The Token Request is form-encoded on the wire, `authorization_details` as JSON.
    if let Ok(input) = std::str::from_utf8(data) {
        if let Ok(request) = from_form_urlencoded_string::<TokenRequest>(input) {
            let encoded = to_form_urlencoded_string(&request).expect("a token request encodes");
            let again: TokenRequest = from_form_urlencoded_string(&encoded).expect("an encoded token request parses");
            assert_eq!(again, request);
        }
    }

    let _ = serde_json::from_slice::<Value>(data);
});
