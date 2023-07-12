use crate::{generate_authorization_code, generate_nonce};
use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{AppendHeaders, IntoResponse},
    routing::{get, post},
    Form, Json, Router,
};
use oid4vci::{
    credential_issuer_metadata::CredentialsSupportedObject,
    credential_offer::{AuthorizationCode, CredentialOffer, CredentialOfferQuery, Grants, PreAuthorizedCode},
    credential_request::CredentialRequest,
    credential_response::CredentialResponse,
    token_request::TokenRequest,
    token_response::TokenResponse,
};
use oid4vp::ClaimFormatDesignation;
use std::{
    net::TcpListener,
    sync::{Arc, Mutex},
};

pub struct Server {
    pub listener: TcpListener,
    pub credential_types: Arc<Mutex<Vec<String>>>,
    pub credentials_supported: Arc<Mutex<CredentialsSupportedObject>>,
    pub authorization_code: Arc<Mutex<Option<AuthorizationCode>>>,
    pub pre_authorized_code: Arc<Mutex<Option<PreAuthorizedCode>>>,
    pub nonce: Arc<Mutex<Option<String>>>,
    pub access_token: Arc<Mutex<Option<String>>>,
}

#[derive(Debug, Clone)]
pub struct ServerState {
    pub credential_types: Arc<Mutex<Vec<String>>>,
    pub credentials_supported: Arc<Mutex<CredentialsSupportedObject>>,
    pub authorization_code: Arc<Mutex<Option<AuthorizationCode>>>,
    pub pre_authorized_code: Arc<Mutex<Option<PreAuthorizedCode>>>,
    pub nonce: Arc<Mutex<Option<String>>>,
    pub access_token: Arc<Mutex<Option<String>>>,
}

impl Server {
    pub fn new(credentials_supported: CredentialsSupportedObject, listener: Option<TcpListener>) -> Result<Self> {
        let listener = listener.unwrap_or_else(|| TcpListener::bind("0.0.0.0:0").unwrap());
        Ok(Self {
            listener,
            credential_types: Arc::new(Mutex::new(vec!["UniversityDegree_JWT".to_string()])),
            credentials_supported: Arc::new(Mutex::new(credentials_supported)),
            authorization_code: Arc::new(Mutex::new(None)),
            pre_authorized_code: Arc::new(Mutex::new(Some(PreAuthorizedCode {
                pre_authorized_code: generate_authorization_code(10),
                user_pin_required: true,
                interval: 5,
            }))),
            nonce: Arc::new(Mutex::new(None)),
            access_token: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn start(&self) {
        let router = self.router(ServerState {
            credential_types: self.credential_types.clone(),
            credentials_supported: self.credentials_supported.clone(),
            authorization_code: self.authorization_code.clone(),
            pre_authorized_code: self.pre_authorized_code.clone(),
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

    pub fn uri(&self) -> String {
        format!("http://{}", self.listener.local_addr().unwrap())
    }

    pub fn credential_offer_uri(&self) -> String {
        // TODO: dynamically create this.
        CredentialOfferQuery::CredentialOffer(CredentialOffer {
            credential_issuer: self.uri(),
            credentials: self.credential_types.lock().unwrap().clone(),
            grants: Some(Grants {
                authorization_code: self.authorization_code.lock().unwrap().clone(),
                pre_authorized_code: self.pre_authorized_code.lock().unwrap().clone(),
            }),
        })
        .to_string()
    }

    fn router(&self, server_state: ServerState) -> Router {
        Router::new()
            .route(
                "/.well-known/openid-credential-issuer",
                get(|State(server_state): State<ServerState>| async move {
                    (
                        StatusCode::OK,
                        Json(server_state.credentials_supported.lock().unwrap().clone()),
                    )
                }),
            )
            .route(
                "/token",
                post(
                    |State(server_state): State<ServerState>, Form(token_request): Form<TokenRequest>| async move {
                        match server_state.pre_authorized_code.lock().unwrap().take() {
                            Some(pre_authorized_code)
                                if pre_authorized_code.pre_authorized_code == token_request.pre_authorized_code =>
                            {
                                (
                                    StatusCode::OK,
                                    AppendHeaders([("Cache-Control", "no-store")]),
                                    Json(TokenResponse {
                                        // TODO: dynamically create this.
                                        access_token: "eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ".to_string(),
                                        token_type: "bearer".to_string(),
                                        expires_in: Some(86400),
                                        refresh_token: None,
                                        scope: None,
                                        c_nonce: Some(generate_nonce(16)),
                                        c_nonce_expires_in: Some(86400),
                                    }),
                                )
                                    .into_response()
                            }
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
                post(|Json(_credential_request): Json<CredentialRequest>| async move {
                    (
                        StatusCode::OK,
                        AppendHeaders([("Cache-Control", "no-store")]),
                        Json(CredentialResponse {
                            format: ClaimFormatDesignation::JwtVcJson,
                            credential: Some(serde_json::json!("\"LUpixVCWJk0eOt4CXQe1NXK....WZwmhmn9OQp6YxX0a2L\"")),
                            transaction_id: None,
                            c_nonce: Some(generate_nonce(16)),
                            c_nonce_expires_in: Some(86400),
                        }),
                    )
                }),
            )
            .with_state(server_state)
    }
}
