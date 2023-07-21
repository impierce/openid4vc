use crate::{generate_authorization_code, generate_nonce};
use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
    Form, Json, Router,
};
use identity_credential::credential::Credential;
use oid4vci::{
    authorization_server_metadata::AuthorizationServerMetadata,
    credential_definition::CredentialDefinition,
    credential_issuer::{self, CredentialIssuer, MemStorage, Storage},
    credential_issuer_metadata::CredentialIssuerMetadata,
    credential_offer::{AuthorizationCode, CredentialOffer, CredentialOfferQuery, Grants, PreAuthorizedCode},
    credential_request::CredentialRequest,
    credential_response::CredentialResponse,
    token_request::TokenRequest,
    token_response::TokenResponse,
    CredentialFormat, JwtVcJson, JwtVcJsonParameters,
};
use oid4vp::{token, ClaimFormatDesignation};
use reqwest::Url;
use std::{
    net::TcpListener,
    sync::{Arc, Mutex},
};

pub struct Server<S: Storage> {
    pub listener: TcpListener,
    pub credential_issuer: Arc<Mutex<CredentialIssuer<S>>>,
    pub credential_types: Arc<Mutex<Vec<serde_json::Value>>>,
    pub nonce: Arc<Mutex<Option<String>>>,
    pub access_token: Arc<Mutex<Option<String>>>,
}

#[derive(Debug, Clone)]
pub struct ServerState<S: Storage> {
    pub credential_issuer: Arc<Mutex<CredentialIssuer<S>>>,
    pub credential_types: Arc<Mutex<Vec<serde_json::Value>>>,
    pub nonce: Arc<Mutex<Option<String>>>,
    pub access_token: Arc<Mutex<Option<String>>>,
}

impl<S: Storage + Clone> Server<S> {
    pub fn new(
        mut credential_issuer_metadata: CredentialIssuerMetadata,
        listener: Option<TcpListener>,
        storage: S,
    ) -> Result<Self> {
        let listener = listener.unwrap_or_else(|| TcpListener::bind("127.0.0.1:0").unwrap());
        let issuer_url: Url = format!("http://{:?}", listener.local_addr()?).parse()?;
        credential_issuer_metadata.credential_issuer = issuer_url.clone();
        credential_issuer_metadata.credential_endpoint = format!("{issuer_url}credential").parse()?;
        Ok(Self {
            listener,
            credential_issuer: Arc::new(Mutex::new(CredentialIssuer {
                metadata: credential_issuer_metadata.clone(),
                authorization_server_metadata: AuthorizationServerMetadata {
                    issuer: issuer_url.clone(),
                    authorization_endpoint: format!("{issuer_url}authorize").parse()?,
                    token_endpoint: format!("{issuer_url}token").parse()?,
                    ..Default::default()
                },
                storage,
            })),
            credential_types: Arc::new(Mutex::new(vec![serde_json::to_value(CredentialFormat {
                format: JwtVcJson,
                parameters: JwtVcJsonParameters {
                    credential_definition: CredentialDefinition {
                        type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                        credential_subject: None,
                    },
                },
            })
            .unwrap()])),
            nonce: Arc::new(Mutex::new(None)),
            access_token: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn start(&self) {
        let router = self.router(ServerState {
            credential_issuer: self.credential_issuer.clone(),
            credential_types: self.credential_types.clone(),
            nonce: self.nonce.clone(),
            access_token: self.access_token.clone(),
        });
        let listener = self.listener.try_clone().unwrap();

        tokio::spawn(async move {
            axum::Server::from_tcp(listener)
                .unwrap()
                .serve(router.into_make_service())
                .await
                .unwrap()
        });
    }

    pub fn credential_offer_uri(&self) -> String {
        let credential_issuer = self
            .credential_issuer
            .lock()
            .unwrap()
            .metadata
            .credential_issuer
            .clone();

        let credentials = self.credential_types.lock().unwrap().clone();
        let authorization_code = self.credential_issuer.lock().unwrap().storage.get_authorization_code();
        let pre_authorized_code = self.credential_issuer.lock().unwrap().storage.get_pre_authorized_code();

        // TODO: dynamically create this.
        CredentialOfferQuery::CredentialOffer(CredentialOffer {
            credential_issuer,
            credentials,
            grants: Some(Grants {
                authorization_code,
                pre_authorized_code,
            }),
        })
        .to_string()
    }

    fn router(&self, server_state: ServerState<S>) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(|State(server_state): State<ServerState<S>>| async move {
                    (
                        StatusCode::OK,
                        Json(
                            server_state
                                .credential_issuer
                                .lock()
                                .unwrap()
                                .authorization_server_metadata
                                .clone(),
                        ),
                    )
                }),
            )
            .route(
                "/.well-known/openid-credential-issuer",
                get(|State(server_state): State<ServerState<S>>| async move {
                    (
                        StatusCode::OK,
                        Json(server_state.credential_issuer.lock().unwrap().metadata.clone()),
                    )
                }),
            )
            .route(
                "/token",
                post(
                    |State(server_state): State<ServerState<S>>, Form(token_request): Form<TokenRequest>| async move {
                        match server_state
                            .credential_issuer
                            .lock()
                            .unwrap()
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
                    |Json(credential_request): Json<CredentialRequest<JwtVcJson>>| async move {
                        dbg!(&credential_request);
                        (
                            StatusCode::OK,
                            AppendHeaders([("Cache-Control", "no-store")]),
                            Json(CredentialResponse {
                                format: ClaimFormatDesignation::JwtVcJson,
                                credential: Some(serde_json::json!(
                                    "\"LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L\""
                                )),
                                transaction_id: None,
                                c_nonce: Some(generate_nonce(16)),
                                c_nonce_expires_in: Some(86400),
                            }),
                        )
                    },
                ),
            )
            .with_state(server_state)
    }
}
