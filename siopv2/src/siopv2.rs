use crate::authorization_request::{
    AuthorizationRequestBuilder, AuthorizationRequestParameters, ClientMetadataParameters,
};
use crate::claims::StandardClaimsValues;
use crate::token::id_token::IdToken;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, Header};
use oid4vc_core::client_metadata::ClientMetadataResource;
use oid4vc_core::openid4vc_extension::{OpenID4VC, RequestHandle, ResponseHandle};
use oid4vc_core::{authorization_response::AuthorizationResponse, jwt, openid4vc_extension::Extension, Subject};
use oid4vc_core::{SubjectSyntaxType, Validator};
use reqwest_middleware::ClientBuilder;
use reqwest_retry::policies::ExponentialBackoff;
use reqwest_retry::RetryTransientMiddleware;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// This is the [`RequestHandle`] for the [`SIOPv2`] extension.
#[derive(Debug, PartialEq, Clone)]
pub struct RequestHandler {}
impl RequestHandle for RequestHandler {
    type Parameters = AuthorizationRequestParameters;
    type Builder = AuthorizationRequestBuilder;
}

/// This is the [`ResponseHandle`] for the [`SIOPv2`] extension.
#[derive(Debug, PartialEq, Clone)]
pub struct ResponseHandler {}
impl ResponseHandle for ResponseHandler {
    type Input = StandardClaimsValues;
    type Parameters = AuthorizationResponseParameters;
    type ResponseItem = IdToken;
}

/// This is the [`Extension`] implementation for the [`SIOPv2`] extension.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SIOPv2;
impl OpenID4VC for SIOPv2 {}
impl Extension for SIOPv2 {
    type RequestHandle = RequestHandler;
    type ResponseHandle = ResponseHandler;

    async fn generate_token(
        subject: Arc<dyn Subject>,
        client_id: &str,
        extension_parameters: &<Self::RequestHandle as RequestHandle>::Parameters,
        user_input: &<Self::ResponseHandle as ResponseHandle>::Input,
        subject_syntax_type: impl TryInto<SubjectSyntaxType>,
        signing_algorithm: impl TryInto<Algorithm>,
    ) -> anyhow::Result<Vec<String>> {
        let signing_algorithm = signing_algorithm
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert the signing algorithm"))?;

        let subject_syntax_type_string = subject_syntax_type
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert the subject syntax type"))?
            .to_string();

        let subject_identifier = subject
            .identifier(&subject_syntax_type_string, signing_algorithm)
            .await?;

        let id_token = IdToken::builder()
            .iss(subject_identifier.clone())
            .sub(subject_identifier)
            .aud(client_id)
            .nonce(extension_parameters.nonce.to_owned())
            // TODO: make this configurable.
            .exp((Utc::now() + Duration::minutes(10)).timestamp())
            .iat((Utc::now()).timestamp())
            .claims(user_input.clone())
            .build()?;

        let jwt = jwt::encode(
            subject.clone(),
            Header::new(signing_algorithm),
            id_token,
            &subject_syntax_type_string,
        )
        .await?;

        Ok(vec![jwt])
    }

    // TODO: combine this function with `get_relying_party_supported_syntax_types`.
    async fn get_relying_party_supported_algorithms(
        authorization_request: &<Self::RequestHandle as RequestHandle>::Parameters,
    ) -> anyhow::Result<Vec<Algorithm>> {
        let client_metadata = match &authorization_request.client_metadata {
            // Fetch the client metadata from the given URI.
            ClientMetadataResource::ClientMetadataUri(client_metadata_uri) => {
                let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
                let client = ClientBuilder::new(reqwest::Client::new())
                    .with(RetryTransientMiddleware::new_with_policy(retry_policy))
                    .build();
                let client_metadata: ClientMetadataResource<ClientMetadataParameters> =
                    client.get(client_metadata_uri).send().await?.json().await?;
                client_metadata
            }
            client_metadata => client_metadata.clone(),
        };

        match client_metadata {
            ClientMetadataResource::ClientMetadataUri(_) => unreachable!(),
            ClientMetadataResource::ClientMetadata { extension, .. } => {
                match extension.id_token_signed_response_alg {
                    Some(alg) => Ok(vec![alg]),
                    // TODO: default to RS256
                    None => Ok(vec![Algorithm::EdDSA]),
                }
            }
        }
    }

    async fn get_relying_party_supported_syntax_types(
        authorization_request: &<Self::RequestHandle as RequestHandle>::Parameters,
    ) -> anyhow::Result<Vec<SubjectSyntaxType>> {
        let client_metadata = match &authorization_request.client_metadata {
            // Fetch the client metadata from the given URI.
            ClientMetadataResource::ClientMetadataUri(client_metadata_uri) => {
                let retry_policy = ExponentialBackoff::builder().build_with_max_retries(5);
                let client = ClientBuilder::new(reqwest::Client::new())
                    .with(RetryTransientMiddleware::new_with_policy(retry_policy))
                    .build();
                let client_metadata: ClientMetadataResource<ClientMetadataParameters> =
                    client.get(client_metadata_uri).send().await?.json().await?;
                client_metadata
            }
            client_metadata => client_metadata.clone(),
        };

        match client_metadata {
            ClientMetadataResource::ClientMetadataUri(_) => unreachable!(),
            ClientMetadataResource::ClientMetadata {
                extension:
                    ClientMetadataParameters {
                        subject_syntax_types_supported,
                        ..
                    },
                ..
            } => Ok(subject_syntax_types_supported),
        }
    }

    fn build_authorization_response(
        jwts: Vec<String>,
        _user_input: <Self::ResponseHandle as ResponseHandle>::Input,
        redirect_uri: String,
        state: Option<String>,
    ) -> anyhow::Result<AuthorizationResponse<Self>> {
        let extension = AuthorizationResponseParameters {
            id_token: jwts[0].to_string(),
        };

        Ok(AuthorizationResponse {
            redirect_uri,
            state,
            extension,
        })
    }

    async fn decode_authorization_response(
        validator: Validator,
        authorization_response: &AuthorizationResponse<Self>,
    ) -> anyhow::Result<<Self::ResponseHandle as ResponseHandle>::ResponseItem> {
        let token = authorization_response.extension.id_token.clone();
        validator.decode(token).await
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct AuthorizationResponseParameters {
    pub id_token: String,
}
