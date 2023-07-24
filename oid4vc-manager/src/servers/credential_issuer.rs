use crate::{managers::credential_issuer::CredentialIssuerManager, storage::Storage};
use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
    Form, Json, Router,
};
use axum_auth::AuthBearer;
use oid4vc_core::{Decoder, Subjects};
use oid4vci::{
    authorization_request::AuthorizationRequest,
    credential_format_profiles::w3c_verifiable_credentials::jwt_vc_json::JwtVcJson,
    credential_request::CredentialRequest, token_request::TokenRequest,
};
use tokio::task::JoinHandle;

pub struct Server<S>
where
    S: Storage,
{
    pub credential_issuer_manager: CredentialIssuerManager<S>,
    pub server: Option<JoinHandle<()>>,
}

impl<S: Storage + Clone> Server<S> {
    pub fn setup(credential_issuer_manager: CredentialIssuerManager<S>) -> Result<Self> {
        Ok(Self {
            credential_issuer_manager,
            server: None,
        })
    }

    pub fn start_server(&mut self) -> Result<()> {
        // TODO: fix this
        let credential_issuer_manager = self.credential_issuer_manager.clone();
        let listener = credential_issuer_manager.listener.try_clone()?;

        self.server.replace(tokio::spawn(async move {
            axum::Server::from_tcp(listener)
                .unwrap()
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
                        .with_state(credential_issuer_manager)
                        .into_make_service(),
                )
                .await
                .unwrap()
        }));
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

async fn oauth_authorization_server<S: Storage>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S>>,
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

async fn openid_credential_issuer<S: Storage>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S>>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(credential_issuer_manager.credential_issuer.metadata),
    )
}

async fn authorize<S: Storage>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S>>,
    Json(_authorization_request): Json<AuthorizationRequest<JwtVcJson>>,
) -> impl IntoResponse {
    (
        // TODO: should be 302 Found
        StatusCode::OK,
        Json(credential_issuer_manager.storage.get_authorization_response().unwrap()),
    )
}

async fn token<S: Storage>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S>>,
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

async fn credential<S: Storage>(
    State(credential_issuer_manager): State<CredentialIssuerManager<S>>,
    AuthBearer(access_token): AuthBearer,
    Json(credential_request): Json<CredentialRequest<JwtVcJson>>,
) -> impl IntoResponse {
    let proof = credential_issuer_manager
        .credential_issuer
        .validate_proof(
            credential_request.proof.unwrap(),
            Decoder::from(&Subjects::try_from([credential_issuer_manager.credential_issuer.subject.clone()]).unwrap()),
        )
        .await
        .unwrap();
    // TODO: validate credential request
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
                    credential_issuer_manager.credential_issuer.subject.clone(),
                )
                .unwrap(),
        ),
    )
}
