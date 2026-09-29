#![cfg(feature = "utoipa")]

use oid4vci::{
    authorization_request::AuthorizationRequest,
    credential_issuer::{
        authorization_server_metadata::AuthorizationServerMetadata,
        credential_issuer_metadata::CredentialIssuerMetadata,
    },
    credential_offer::CredentialOfferParameters,
    credential_request::CredentialRequest,
    credential_response::CredentialResponse,
    errors::{CredentialErrorResponse, NotificationErrorResponse, OID4VCError, TokenErrorResponse},
    interactive_authorization_request::{InteractiveAuthorizationFollowUpRequest, InteractiveAuthorizationRequest},
    interactive_authorization_response::InteractiveAuthorizationResponse,
    nonce_response::NonceResponse,
    notification_request::NotificationRequest,
    token_request::TokenRequest,
    token_response::TokenResponse,
    wallet::AuthorizationRequestByReference,
};
use serde_json::Value;
use std::collections::BTreeSet;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(components(schemas(
    AuthorizationServerMetadata,
    CredentialIssuerMetadata,
    CredentialRequest,
    CredentialResponse,
    CredentialOfferParameters,
    AuthorizationRequest,
    InteractiveAuthorizationRequest,
    InteractiveAuthorizationFollowUpRequest,
    InteractiveAuthorizationResponse,
    TokenRequest,
    TokenResponse,
    NonceResponse,
    NotificationRequest,
    OID4VCError<TokenErrorResponse>,
    OID4VCError<CredentialErrorResponse>,
    OID4VCError<NotificationErrorResponse>,
)))]
struct ProtocolSchemas;

fn collect_references(value: &Value, references: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                references.insert(reference.to_string());
            }
            for value in object.values() {
                collect_references(value, references);
            }
        }
        Value::Array(array) => {
            for value in array {
                collect_references(value, references);
            }
        }
        _ => {}
    }
}

#[test]
fn aggregate_protocol_schema_has_no_unresolved_references() {
    let openapi = ProtocolSchemas::openapi();
    let document = serde_json::to_value(&openapi).unwrap();
    let schemas = document["components"]["schemas"].as_object().unwrap();
    let mut references = BTreeSet::new();
    collect_references(&document, &mut references);

    let unresolved: Vec<_> = references
        .into_iter()
        .filter_map(|reference| {
            reference
                .strip_prefix("#/components/schemas/")
                .filter(|name| !schemas.contains_key(*name))
                .map(str::to_string)
        })
        .collect();

    assert!(unresolved.is_empty(), "unresolved schema references: {unresolved:?}");
}

#[test]
fn aggregate_protocol_schema_preserves_wire_shapes_and_constraints() {
    let document = serde_json::to_value(ProtocolSchemas::openapi()).unwrap();
    let schemas = &document["components"]["schemas"];
    let serialized = serde_json::to_string(schemas).unwrap();

    for format in [
        "jwt_vc_json",
        "jwt_vc_json-ld",
        "ldp_vc",
        "mso_mdoc",
        "dc+sd-jwt",
        "vc+sd-jwt",
    ] {
        assert!(serialized.contains(format), "missing credential format {format}");
    }

    assert_eq!(schemas["CredentialFormats"]["oneOf"].as_array().unwrap().len(), 6);
    assert_eq!(
        schemas["CredentialRequest"]["allOf"][0]["$ref"],
        "#/components/schemas/CredentialIdentifierOrCredentialConfigurationId"
    );
    assert_eq!(schemas["CredentialResponseType"]["oneOf"].as_array().unwrap().len(), 2);
    assert_eq!(
        schemas["TokenRequest"]["oneOf"][1]["properties"]["grant_type"]["enum"][0],
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    );
    assert!(schemas["Grants"]["properties"]
        .get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
        .is_some());
    assert_eq!(schemas["BatchSize"]["minimum"], 2);
    assert_eq!(schemas["CredentialConfigurationIds"]["minItems"], 1);
    assert_eq!(schemas["ClaimPathPointer"]["minItems"], 1);
    assert_eq!(schemas["ClaimPathElement"]["oneOf"][1]["minimum"], 0);
    assert_eq!(schemas["ClaimPathElement"]["oneOf"][2]["type"], "null");
    assert_eq!(schemas["InteractionType"]["oneOf"][2]["type"], "string");
    assert_eq!(
        schemas["AuthorizationServerMetadata"]["properties"]["issuer"]["format"],
        "uri"
    );
}

#[test]
fn aggregate_protocol_schema_serializes_to_json_and_yaml() {
    let openapi = ProtocolSchemas::openapi();

    assert!(serde_json::to_string(&openapi).is_ok());
    assert!(openapi.to_yaml().is_ok());
}

#[test]
fn authorization_request_by_reference_is_described_as_query_parameters() {
    let parameters = <AuthorizationRequestByReference as utoipa::IntoParams>::into_params(|| None);
    let parameters = serde_json::to_value(parameters).unwrap();

    assert_eq!(parameters[0]["name"], "client_id");
    assert_eq!(parameters[0]["in"], "query");
    assert_eq!(parameters[1]["name"], "request_uri");
    assert_eq!(parameters[1]["in"], "query");
}
