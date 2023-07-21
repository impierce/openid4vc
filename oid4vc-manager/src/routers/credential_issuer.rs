use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
    Form, Json, Router,
};
use axum_auth::AuthBearer;
use oid4vci::{
    authorization_server_metadata::AuthorizationServerMetadata,
    credential_issuer::{CredentialIssuer, Storage},
    credential_issuer_metadata::CredentialIssuerMetadata,
    credential_offer::{CredentialOffer, CredentialOfferQuery, Grants},
    credential_request::CredentialRequest,
    token_request::TokenRequest,
    CredentialFormat, JwtVcJson, credentials_supported::CredentialsSupportedJson,
};
use reqwest::Url;
use std::net::TcpListener;
use tokio::task::JoinHandle;

pub struct CredentialIssuerManager<S: Storage> {
    credential_issuer: CredentialIssuer<S>,
    listener: TcpListener,
    server: Option<JoinHandle<()>>,
}

impl<S: Storage + Clone> CredentialIssuerManager<S> {
    pub fn run(
        credentials_supported: Vec<CredentialsSupportedJson>,
        listener: Option<TcpListener>,
        storage: S,
    ) -> Result<Self> {
        let listener = listener.unwrap_or_else(|| TcpListener::bind("127.0.0.1:0").unwrap());
        let issuer_url: Url = format!("http://{:?}", listener.local_addr()?).parse()?;

        Ok(Self {
            credential_issuer: CredentialIssuer {
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
                storage,
            },
            listener,
            server: None,
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
                authorization_code: self.credential_issuer.storage.get_authorization_code(),
                pre_authorized_code: self.credential_issuer.storage.get_pre_authorized_code(),
            }),
        })
        .to_string())
    }

    pub fn run_server(&mut self) -> Result<()> {
        let listener = self.listener.try_clone()?;
        let credential_issuer = self.credential_issuer.clone();

        self.server
            .replace(tokio::spawn(async move {
                axum::Server::from_tcp(listener)
                    .unwrap()
                    .serve(Router::new()
                    .route(
                        "/.well-known/oauth-authorization-server",
                        get(|State(credential_issuer): State<CredentialIssuer<S>>| async move {
                            (
                                StatusCode::OK,
                                Json(
                                        credential_issuer
                                        .authorization_server_metadata
                                        .clone(),
                                ),
                            )
                        }),
                    )
                    .route(
                        "/.well-known/openid-credential-issuer",
                        get(|State(credential_issuer): State<CredentialIssuer<S>>| async move {
                            (
                                StatusCode::OK,
                                Json(credential_issuer.metadata.clone()),
                            )
                        }),
                    )
                    .route(
                        "/token",
                        post(
                            |State(credential_issuer): State<CredentialIssuer<S>>, Form(token_request): Form<TokenRequest>| async move {
                                match
                                    credential_issuer
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
                            |State(credential_issuer): State<CredentialIssuer<S>>,
                             AuthBearer(access_token): AuthBearer,
                             Json(_credential_request): Json<CredentialRequest<JwtVcJson>>| async move {
                                // TODO: validate credential request
                                (
                                    StatusCode::OK,
                                    AppendHeaders([("Cache-Control", "no-store")]),
                                    Json(
                                            credential_issuer
                                            .storage
                                            .get_credential_response(access_token)
                                            .unwrap(),
                                    ),
                                )
                            },
                        ),
                    )
                    .with_state(credential_issuer).into_make_service())
                    .await.unwrap()
            }));
        Ok(())
    }

    pub fn stop_server(&mut self) -> Result<()> {
        self.server.take().unwrap().abort();
        Ok(())
    }
}
