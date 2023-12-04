use crate::authorization_request::{AuthorizationRequestBuilder, AuthorizationRequestParameters};
use crate::oid4vp_params::{serde_oid4vp_response, Oid4vpParams};
use chrono::{Duration, Utc};
pub use dif_presentation_exchange::{
    evaluate_input, ClaimFormatDesignation, InputDescriptor, InputDescriptorMappingObject, PathNested,
    PresentationDefinition, PresentationSubmission,
};
use futures::{executor::block_on, future::join_all};
use identity_credential::{credential::Jwt, presentation::Presentation};
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::openid4vc_extension::{OpenID4VC, RequestHandle, ResponseHandle};
use oid4vc_core::{
    authorization_response::AuthorizationResponse, jwt, openid4vc_extension::Extension, serialize_unit_struct, Decoder,
    Subject,
};
use oid4vci::VerifiableCredentialJwt;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::sync::Arc;

/// This is the [`RequestHandle`] for the [`OID4VP`] extension.
#[derive(Debug, PartialEq)]
pub struct RequestHandler {}
impl RequestHandle for RequestHandler {
    type ResponseType = VpToken;
    type Parameters = AuthorizationRequestParameters;
    type Builder = AuthorizationRequestBuilder;
}

/// This is the [`ResponseHandle`] for the [`OID4VP`] extension.
#[derive(Debug, PartialEq)]
pub struct ResponseHandler {}
impl ResponseHandle for ResponseHandler {
    type Input = AuthorizationResponseInput;
    type Parameters = AuthorizationResponseParameters;
    type ResponseItem = Vec<VerifiableCredentialJwt>;
}

// Unit struct used for the `response_type` parameter.
#[derive(Debug, PartialEq, Default, DeserializeFromStr, SerializeDisplay, Clone)]
pub struct VpToken;
serialize_unit_struct!("vp_token", VpToken);

/// This is the [`Extension`] implementation for the [`OID4VP`] extension.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct OID4VP;
impl OpenID4VC for OID4VP {}
impl Extension for OID4VP {
    type RequestHandle = RequestHandler;
    type ResponseHandle = ResponseHandler;

    fn generate_token(
        subject: Arc<dyn Subject>,
        client_id: &str,
        extension_parameters: &<Self::RequestHandle as RequestHandle>::Parameters,
        user_input: &<Self::ResponseHandle as ResponseHandle>::Input,
    ) -> anyhow::Result<Vec<String>> {
        let subject_identifier = subject.identifier()?;

        let vp_token = crate::token::vp_token::VpToken::builder()
            .iss(subject_identifier.clone())
            .sub(subject_identifier)
            .aud(client_id)
            .nonce(extension_parameters.nonce.to_owned())
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .verifiable_presentation(user_input.verifiable_presentation.clone())
            .build()?;

        let jwt = jwt::encode(subject.clone(), Header::new(Algorithm::EdDSA), vp_token)?;
        Ok(vec![jwt])
    }

    fn build_authorization_response(
        jwts: Vec<String>,
        user_input: <Self::ResponseHandle as ResponseHandle>::Input,
        redirect_uri: String,
        state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        Ok(AuthorizationResponse {
            redirect_uri,
            state,
            extension: AuthorizationResponseParameters {
                oid4vp_parameters: Oid4vpParams::Params {
                    vp_token: jwts.get(0).unwrap().to_owned(),
                    presentation_submission: user_input.presentation_submission,
                },
            },
        })
    }

    fn decode_authorization_response(
        decoder: Decoder,
        response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<<Self::ResponseHandle as ResponseHandle>::ResponseItem> {
        let vp_token: crate::token::vp_token::VpToken = match &response.extension.oid4vp_parameters {
            Oid4vpParams::Jwt { .. } => todo!(),
            Oid4vpParams::Params { vp_token, .. } => block_on(decoder.decode(vp_token.to_owned()))?,
        };

        block_on(async move {
            join_all(
                vp_token
                    .verifiable_presentation()
                    .verifiable_credential
                    .iter()
                    .map(|vc| async { decoder.decode(vc.as_str().to_owned()).await }),
            )
            .await
            .into_iter()
            .collect()
        })
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct AuthorizationResponseParameters {
    #[serde(flatten, with = "serde_oid4vp_response")]
    pub oid4vp_parameters: Oid4vpParams,
}

pub struct AuthorizationResponseInput {
    pub verifiable_presentation: Presentation<Jwt>,
    pub presentation_submission: PresentationSubmission,
}
