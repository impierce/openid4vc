use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
    Form, Json, Router,
};
use axum_auth::AuthBearer;
use oid4vc_core::{Decoder, Subject, Subjects};
use oid4vci::{
    credential_format::CredentialFormat,
    credential_format_profiles::w3c_verifiable_credentials::jwt_vc_json::JwtVcJson,
    credential_issuer::{
        authorization_server_metadata::AuthorizationServerMetadata,
        credential_issuer_metadata::CredentialIssuerMetadata, CredentialIssuer, Storage,
    },
    credential_offer::{CredentialOffer, CredentialOfferQuery, Grants},
    credential_request::CredentialRequest,
    credentials_supported::CredentialsSupportedJson,
    token_request::TokenRequest,
};
use reqwest::Url;
use std::{net::TcpListener, sync::Arc};
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
                    .serve(Router::new()
                    .route(
                        "/.well-known/oauth-authorization-server",
                        get(|State(credential_issuer_manager): State<CredentialIssuerManager<S>>| async move {
                            (
                                StatusCode::OK,
                                Json(
                                    credential_issuer_manager.credential_issuer
                                        .authorization_server_metadata
                                        .clone(),
                                ),
                            )
                        }),
                    )
                    .route(
                        "/.well-known/openid-credential-issuer",
                        get(|State(credential_issuer_manager): State<CredentialIssuerManager<S>>| async move {
                            (
                                StatusCode::OK,
                                Json(credential_issuer_manager.credential_issuer.metadata.clone()),
                            )
                        }),
                    )
                    .route(
                        "/token",
                        post(
                            |State(credential_issuer_manager): State<CredentialIssuerManager<S>>, Form(token_request): Form<TokenRequest>| async move {
                                match
                                credential_issuer_manager
                                    .storage
                                    .get_token_response(token_request.pre_authorized_code)
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
                            },
                        ),
                    )
                    .route(
                        "/credential",
                        post(
                            |State(credential_issuer_manager): State<CredentialIssuerManager<S>>,
                             AuthBearer(access_token): AuthBearer,
                             Json(credential_request): Json<CredentialRequest<JwtVcJson>>| async move {
                                let proof = credential_issuer_manager
                                    .credential_issuer.validate_proof(credential_request.proof.unwrap(), Decoder::from(&Subjects::try_from([credential_issuer_manager.credential_issuer.subject.clone()]).unwrap()))
                                    .await
                                    .unwrap();
                                // TODO: validate credential request
                                (
                                    StatusCode::OK,
                                    AppendHeaders([("Cache-Control", "no-store")]),
                                    Json(
                                        credential_issuer_manager
                                            .storage.get_credential_response(access_token, proof.rfc7519_claims.iss().as_ref().unwrap().parse().unwrap(), credential_issuer_manager.credential_issuer.metadata.credential_issuer.clone(), credential_issuer_manager.credential_issuer.subject.clone())
                                            .unwrap(),
                                    ),
                                )
                            },
                        ),
                    )
                    .with_state(credential_issuer_manager).into_make_service())
                    .await.unwrap()
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

#[derive(Clone)]
pub struct CredentialIssuerManager<S: Storage> {
    pub credential_issuer: CredentialIssuer,
    pub subjects: Arc<Subjects>,
    pub storage: S,
    pub listener: Arc<TcpListener>,
}

impl<S: Storage + Clone> CredentialIssuerManager<S> {
    pub fn new<const N: usize>(
        credentials_supported: Vec<CredentialsSupportedJson>,
        listener: Option<TcpListener>,
        storage: S,
        subjects: [Arc<dyn Subject>; N],
    ) -> Result<Self> {
        let listener = listener.unwrap_or_else(|| TcpListener::bind("127.0.0.1:0").unwrap());
        let issuer_url: Url = format!("http://{:?}", listener.local_addr()?).parse()?;
        Ok(Self {
            credential_issuer: CredentialIssuer {
                subject: subjects
                    .get(0)
                    .ok_or_else(|| anyhow::anyhow!("No subjects found."))?
                    .clone(),
                metadata: CredentialIssuerMetadata {
                    credential_issuer: issuer_url.clone(),
                    authorization_server: None,
                    credential_endpoint: format!("{issuer_url}credential").parse()?,
                    batch_credential_endpoint: None,
                    deferred_credential_endpoint: None,
                    credentials_supported,
                    display: None,
                },
                authorization_server_metadata: AuthorizationServerMetadata {
                    issuer: issuer_url.clone(),
                    authorization_endpoint: format!("{issuer_url}authorize").parse()?,
                    token_endpoint: format!("{issuer_url}token").parse()?,
                    ..Default::default()
                },
            },
            subjects: Arc::new(Subjects::try_from(subjects)?),
            storage,
            listener: Arc::new(listener),
        })
    }

    pub fn credential_offer_uri(&self) -> Result<String> {
        // TODO: fix this
        let credentials: CredentialFormat<JwtVcJson> = serde_json::from_value(
            serde_json::to_value(self.credential_issuer.metadata.credentials_supported.get(0).unwrap()).unwrap(),
        )
        .unwrap();

        Ok(CredentialOfferQuery::CredentialOffer(CredentialOffer {
            credential_issuer: self.credential_issuer.metadata.credential_issuer.clone(),
            credentials: vec![serde_json::to_value(credentials)?],
            grants: Some(Grants {
                authorization_code: self.storage.get_authorization_code(),
                pre_authorized_code: self.storage.get_pre_authorized_code(),
            }),
        })
        .to_string())
    }
}
