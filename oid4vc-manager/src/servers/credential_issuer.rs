use std::time::Duration;

use crate::{managers::credential_issuer::CredentialIssuerManager, storage::Storage};
use anyhow::Result;
use axum::{
    extract::State,
    http::{header::CONTENT_TYPE, Method, StatusCode},
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
    Form, Json, Router,
};
use axum_auth::AuthBearer;
use oid4vc_core::{Decoder, Subjects};
use oid4vci::{
    authorization_request::AuthorizationRequest,
    credential_format_profiles::CredentialFormatCollection,
    credential_request::{BatchCredentialRequest, CredentialRequest},
    credential_response::BatchCredentialResponse,
    token_request::TokenRequest,
};
use serde::de::DeserializeOwned;
use tokio::task::JoinHandle;
use tower_http::cors::AllowOrigin;

pub struct Server<S, CFC>
where
    S: Storage<CFC>,
    CFC: CredentialFormatCollection,
{
    pub credential_issuer_manager: CredentialIssuerManager<S, CFC>,
    pub server: Option<JoinHandle<()>>,
    pub extension: Option<Router<CredentialIssuerManager<S, CFC>>>,
    pub detached: bool,
}

impl<S: Storage<CFC> + Clone, CFC: CredentialFormatCollection + Clone + DeserializeOwned + 'static> Server<S, CFC> {
    pub fn setup(
        credential_issuer_manager: CredentialIssuerManager<S, CFC>,
        extension: Option<Router<CredentialIssuerManager<S, CFC>>>,
    ) -> Result<Self> {
        Ok(Self {
            credential_issuer_manager,
            server: None,
            extension,
            detached: false,
        })
    }

    pub fn detached(mut self, detached: bool) -> Self {
        self.detached = detached;
        self
    }

    pub async fn start_server(&mut self) -> Result<()> {
        let credential_issuer_manager = self.credential_issuer_manager.clone();
        let listener = credential_issuer_manager.listener.try_clone()?;
        let extension = self.extension.take();

        let server = axum::Server::from_tcp(listener)
            .expect("Failed to start server.")
            .serve(
                Router::new()
                    .route(
                        "/.well-known/oauth-authorization-server",
                        get(oauth_authorization_server),
                    )
                    .route("/.well-known/openid-credential-issuer", get(openid_credential_issuer))
                    .route("/authorize", get(authorize))
                    .route("/token", post(token))
                    .route("/credential", post(credential))
                    .route("/batch_credential", post(batch_credential))
                    .merge(extension.unwrap_or_default())
                    .layer(
                        tower_http::cors::CorsLayer::new()
                            .allow_methods([Method::GET, Method::POST])
                            .allow_origin(AllowOrigin::any())
                            .allow_headers([CONTENT_TYPE])
                            .max_age(Duration::from_secs(3600)),
                    )
                    .with_state(credential_issuer_manager)
                    .into_make_service(),
            );

        if self.detached {
            self.server.replace(tokio::spawn(
                async move { server.await.expect("Failed to start server.") },
            ));
        } else {
            server.await.expect("Failed to start server.")
        }
        Ok(())
    }

    pub fn stop_server(&mut self) -> Result<()> {
        self.server
            .as_ref()
            .ok_or(anyhow::anyhow!("Server not started."))?
            .abort();
        Ok(())
    }
}

async fn oauth_authorization_server<S: Storage<CFC>, CFC: CredentialFormatCollection>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S, CFC>>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(
            credential_issuer_manager
                .credential_issuer
                .authorization_server_metadata,
        ),
    )
}

async fn openid_credential_issuer<S: Storage<CFC>, CFC: CredentialFormatCollection>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S, CFC>>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(credential_issuer_manager.credential_issuer.metadata),
    )
}

async fn authorize<S: Storage<CFC>, CFC: CredentialFormatCollection>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S, CFC>>,
    Json(_authorization_request): Json<AuthorizationRequest<CFC>>,
) -> impl IntoResponse {
    (
        // TODO: should be 302 Found + implement proper error response.
        StatusCode::OK,
        Json(credential_issuer_manager.storage.get_authorization_response().unwrap()),
    )
}

async fn token<S: Storage<CFC>, CFC: CredentialFormatCollection>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S, CFC>>,
    Form(token_request): Form<TokenRequest>,
) -> impl IntoResponse {
    match credential_issuer_manager
        .storage
        .get_token_response(token_request)
        .take()
    {
        Some(token_response) => (
            StatusCode::OK,
            AppendHeaders([("Cache-Control", "no-store")]),
            Json(token_response),
        )
            .into_response(),
        // TODO: handle error response
        _ => (
            StatusCode::BAD_REQUEST,
            AppendHeaders([("Cache-Control", "no-store")]),
            Json("Pre-authorized code not found"),
        )
            .into_response(),
    }
}

async fn credential<S: Storage<CFC>, CFC: CredentialFormatCollection>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S, CFC>>,
    AuthBearer(access_token): AuthBearer,
    Json(credential_request): Json<CredentialRequest<CFC>>,
) -> impl IntoResponse {
    // TODO: The bunch of unwrap's here should be replaced with error responses as described here: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    let proof = credential_issuer_manager
        .credential_issuer
        .validate_proof(
            credential_request.proof.unwrap(),
            Decoder::from(&Subjects::try_from([credential_issuer_manager.credential_issuer.subject.clone()]).unwrap()),
        )
        .await
        .unwrap();
    (
        StatusCode::OK,
        AppendHeaders([("Cache-Control", "no-store")]),
        Json(
            credential_issuer_manager
                .storage
                .get_credential_response(
                    access_token,
                    proof.rfc7519_claims.iss().as_ref().unwrap().parse().unwrap(),
                    credential_issuer_manager
                        .credential_issuer
                        .metadata
                        .credential_issuer
                        .clone(),
                    credential_request.credential_format.clone(),
                    credential_issuer_manager.credential_issuer.subject.clone(),
                )
                .unwrap(),
        ),
    )
}

async fn batch_credential<S: Storage<CFC>, CFC: CredentialFormatCollection>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S, CFC>>,
    AuthBearer(access_token): AuthBearer,
    Json(batch_credential_request): Json<BatchCredentialRequest<CFC>>,
) -> impl IntoResponse {
    let mut credential_responses = vec![];
    for credential_request in batch_credential_request.credential_requests {
        // TODO: The bunch of unwrap's here should be replaced with error responses as described here: https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
        let proof = credential_issuer_manager
            .credential_issuer
            .validate_proof(
                credential_request.proof.unwrap(),
                Decoder::from(
                    &Subjects::try_from([credential_issuer_manager.credential_issuer.subject.clone()]).unwrap(),
                ),
            )
            .await
            .unwrap();

        credential_responses.push(
            credential_issuer_manager
                .storage
                .get_credential_response(
                    access_token.clone(),
                    proof.rfc7519_claims.iss().as_ref().unwrap().parse().unwrap(),
                    credential_issuer_manager
                        .credential_issuer
                        .metadata
                        .credential_issuer
                        .clone(),
                    credential_request.credential_format.clone(),
                    credential_issuer_manager.credential_issuer.subject.clone(),
                )
                .unwrap()
                .credential,
        );
    }

    (
        StatusCode::OK,
        AppendHeaders([("Cache-Control", "no-store")]),
        Json(BatchCredentialResponse {
            credential_responses,
            c_nonce: None,
            c_nonce_expires_in: None,
        }),
    )
}
