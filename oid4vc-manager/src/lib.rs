pub mod managers;
pub mod methods;
pub mod servers;
pub mod storage;

pub use managers::{provider::ProviderManager, relying_party::RelyingPartyManager};
use oid4vp::PresentationDefinition;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use siopv2::{ClaimRequests, ClientMetadata, Scope};

// #[derive(Serialize, Deserialize, Debug)]
// #[serde(deny_unknown_fields)]
// #[serde(untagged)]
// pub enum AuthorizationRequest<E: Extension> {
//     Reference { client_id: String, request_uri: url::Url },
//     Value { client_id: String, request: String },
//     Object(AuthorizationRequestObject<E>),
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct AuthorizationRequestObject<E: Extension> {
//     response_type: E::ResponseType,
//     client_id: String,
//     redirect_uri: url::Url,
//     state: Option<String>,
//     #[serde(flatten)]
//     extension: E::AuthorizationRequest,
// }

// pub trait Extension {
//     type AuthorizationRequest: Serialize + DeserializeOwned + std::fmt::Debug;
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct SIOPv2;
// impl Extension for SIOPv2 {
//     type AuthorizationRequest = SIOPv2AuthorizationRequestParameters;
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct SIOPv2AuthorizationRequestParameters {
//     // TODO: make generic Scope and add it to `AuthorizationRequestObject`.
//     pub scope: Scope,
//     pub response_mode: Option<String>,
//     pub nonce: String,
//     pub claims: Option<ClaimRequests>,
//     // TODO: impl client_metadata_uri.
//     pub client_metadata: Option<ClientMetadata>,
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct OID4VP;
// impl Extension for OID4VP {
//     type AuthorizationRequest = OID4VPAuthorizationRequestParameters;
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct OID4VPAuthorizationRequestParameters {
//     // TODO: impl presentation_definition_uri.
//     pub presentation_definition: PresentationDefinition,
//     pub client_id_scheme: Option<String>,
//     // TODO: impl client_metadata_uri.
//     pub client_metadata: Option<ClientMetadata>,
//     pub nonce: String,
//     pub scope: Option<Scope>,
//     pub response_mode: Option<String>,
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct SIOPv2OID4VP;
// impl Extension for SIOPv2OID4VP {
//     type AuthorizationRequest = SIOPv2OID4VPAuthorizationRequestParameters;
// }

// #[derive(Serialize, Deserialize, Debug)]
// pub struct SIOPv2OID4VPAuthorizationRequestParameters {
//     // TODO: make generic Scope and add it to `AuthorizationRequestObject`.
//     pub scope: Scope,
//     pub claims: Option<ClaimRequests>,
//     // TODO: impl presentation_definition_uri.
//     pub presentation_definition: PresentationDefinition,
//     pub client_id_scheme: Option<String>,
//     // TODO: impl client_metadata_uri.
//     pub client_metadata: Option<ClientMetadata>,
//     pub nonce: String,
//     pub response_mode: Option<String>,
// }

// #[test]
// fn test() {
//     use serde_json::json;

//     let test = json!({
//         "client_id": "did:example:123",
//         "response_type": "id_token",
//         "redirect_uri": "https://example.com",
//         "scope": "openid",
//         "state": "state"
//     });

//     let test: AuthorizationRequest<SIOPv2> = serde_json::from_value(json!(test)).unwrap();

//     dbg!(&test);
// }
