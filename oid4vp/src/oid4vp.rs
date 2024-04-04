use crate::authorization_request::{AuthorizationRequestBuilder, AuthorizationRequestParameters};
use crate::oid4vp_params::{serde_oid4vp_response, Oid4vpParams};
use crate::token::vp_token::VpToken;
use chrono::{Duration, Utc};
pub use dif_presentation_exchange::{
    evaluate_input, ClaimFormatDesignation, InputDescriptor, InputDescriptorMappingObject, PathNested,
    PresentationDefinition, PresentationSubmission,
};
use futures::{executor::block_on, future::join_all};
use identity_credential::{credential::Jwt, presentation::Presentation};
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::openid4vc_extension::{OpenID4VC, RequestHandle, ResponseHandle};
use oid4vc_core::Validator;
use oid4vc_core::{authorization_response::AuthorizationResponse, jwt, openid4vc_extension::Extension, Subject};
use oid4vci::VerifiableCredentialJwt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// This is the [`RequestHandle`] for the [`OID4VP`] extension.
#[derive(Debug, PartialEq, Clone)]
pub struct RequestHandler {}
impl RequestHandle for RequestHandler {
    type Parameters = AuthorizationRequestParameters;
    type Builder = AuthorizationRequestBuilder;
}

/// This is the [`ResponseHandle`] for the [`OID4VP`] extension.
#[derive(Debug, PartialEq, Clone)]
pub struct ResponseHandler {}
impl ResponseHandle for ResponseHandler {
    type Input = AuthorizationResponseInput;
    type Parameters = AuthorizationResponseParameters;
    type ResponseItem = Vec<VerifiableCredentialJwt>;
}

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
        did_method: &str,
    ) -> anyhow::Result<Vec<String>> {
        let subject_identifier = subject.identifier(did_method)?;

        let vp_token = VpToken::builder()
            .iss(subject_identifier.clone())
            .sub(subject_identifier)
            .aud(client_id)
            .nonce(extension_parameters.nonce.to_owned())
            // TODO: make this configurable.
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .verifiable_presentation(user_input.verifiable_presentation.clone())
            .build()?;

        let jwt = jwt::encode(subject.clone(), Header::new(Algorithm::EdDSA), vp_token, did_method)?;
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
                    vp_token: jwts.first().unwrap().to_owned(),
                    presentation_submission: user_input.presentation_submission,
                },
            },
        })
    }

    async fn decode_authorization_response(
        validator: Validator,
        response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<<Self::ResponseHandle as ResponseHandle>::ResponseItem> {
        let vp_token: VpToken = match &response.extension.oid4vp_parameters {
            Oid4vpParams::Jwt { .. } => todo!(),
            Oid4vpParams::Params { vp_token, .. } => block_on(validator.decode(vp_token.to_owned()))?,
        };

        join_all(
            vp_token
                .verifiable_presentation()
                .verifiable_credential
                .iter()
                .map(|vc| validator.decode(vc.as_str().to_owned()))
                .collect::<Vec<_>>(),
        )
        .await
        .into_iter()
        .collect()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationResponseParameters {
    #[serde(flatten, with = "serde_oid4vp_response")]
    pub oid4vp_parameters: Oid4vpParams,
}

pub struct AuthorizationResponseInput {
    pub verifiable_presentation: Presentation<Jwt>,
    pub presentation_submission: PresentationSubmission,
}
