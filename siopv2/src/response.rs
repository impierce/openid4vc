use crate::builder_fn;
use anyhow::{anyhow, Result};
use getset::Getters;
use oid4vp::PresentationSubmission;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

/// Represents the parameters of an OpenID4VP response. It can hold a Verifiable Presentation Token and a Presentation
/// Submission, or a JWT containing them.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum Oid4vpParams {
    Jwt {
        response: String,
    },
    Params {
        vp_token: String,
        presentation_submission: PresentationSubmission,
    },
}

/// Represents an Authorization AuthorizationResponse. It can hold an ID Token, a Verifiable Presentation Token, a Presentation
/// Submission, or a combination of them.
#[skip_serializing_none]
#[derive(Serialize, Default, Deserialize, Debug, Getters, PartialEq)]
pub struct AuthorizationResponse {
    #[serde(skip)]
    #[getset(get = "pub")]
    redirect_uri: String,
    #[getset(get = "pub")]
    id_token: Option<String>,
    #[serde(flatten)]
    #[getset(get = "pub")]
    oid4vp_response: Option<Oid4vpParams>,
    state: Option<String>,
}

impl AuthorizationResponse {
    pub fn builder() -> ResponseBuilder {
        ResponseBuilder::new()
    }
}

#[derive(Default)]
pub struct ResponseBuilder {
    redirect_uri: Option<String>,
    id_token: Option<String>,
    vp_token: Option<String>,
    presentation_submission: Option<PresentationSubmission>,
    oid4vp_response_jwt: Option<String>,
    state: Option<String>,
}

impl ResponseBuilder {
    pub fn new() -> Self {
        ResponseBuilder::default()
    }

    pub fn build(&mut self) -> Result<AuthorizationResponse> {
        let redirect_uri = self
            .redirect_uri
            .take()
            .ok_or(anyhow!("redirect_uri parameter is required."))?;

        let oid4vp_response = match (
            self.vp_token.take(),
            self.presentation_submission.take(),
            self.oid4vp_response_jwt.take(),
        ) {
            (Some(vp_token), Some(presentation_submission), None) => Ok(Some(Oid4vpParams::Params {
                vp_token,
                presentation_submission,
            })),
            (None, None, Some(response)) => Ok(Some(Oid4vpParams::Jwt { response })),
            (None, None, None) => Ok(None),
            (Some(_), None, None) => Err(anyhow!(
                "`presentation_submission` parameter is required when using `vp_token` parameter."
            )),
            (None, Some(_), None) => Err(anyhow!(
                "`vp_token` parameter is required when using `presentation_submission` parameter."
            )),
            _ => Err(anyhow!(
                "`response` parameter can not be used with `vp_token` and `presentation_submission` parameters."
            )),
        }?;

        Ok(AuthorizationResponse {
            redirect_uri,
            id_token: self.id_token.take(),
            oid4vp_response,
            state: self.state.take(),
        })
    }

    builder_fn!(redirect_uri, String);
    builder_fn!(id_token, String);
    builder_fn!(vp_token, String);
    builder_fn!(presentation_submission, PresentationSubmission);
    builder_fn!(oid4vp_response_jwt, String);
    builder_fn!(state, String);
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_valid_response() {
//         assert!(AuthorizationResponse::builder()
//             .redirect_uri("redirect".to_string())
//             .id_token("id_token".to_string())
//             .build()
//             .is_ok());

//         assert!(AuthorizationResponse::builder()
//             .redirect_uri("redirect".to_string())
//             .vp_token("vp_token".to_string())
//             .presentation_submission("presentation_submission".to_string())
//             .build()
//             .is_ok());

//         assert!(AuthorizationResponse::builder()
//             .redirect_uri("redirect".to_string())
//             .id_token("id_token".to_string())
//             .vp_token("vp_token".to_string())
//             .presentation_submission("presentation_submission".to_string())
//             .build()
//             .is_ok());
//     }

//     #[test]
//     fn test_invalid_response() {
//         assert_eq!(
//             AuthorizationResponse::builder()
//                 .id_token("id_token".to_string())
//                 .build()
//                 .unwrap_err()
//                 .to_string(),
//             "redirect_uri parameter is required."
//         );

//         assert_eq!(
//             AuthorizationResponse::builder()
//                 .redirect_uri("redirect".to_string())
//                 .vp_token("vp_token".to_string())
//                 .build()
//                 .unwrap_err()
//                 .to_string(),
//             "`presentation_submission` parameter is required when using `vp_token` parameter."
//         );

//         assert_eq!(
//             AuthorizationResponse::builder()
//                 .redirect_uri("redirect".to_string())
//                 .presentation_submission("presentation_submission".to_string())
//                 .build()
//                 .unwrap_err()
//                 .to_string(),
//             "`vp_token` parameter is required when using `presentation_submission` parameter."
//         );

//         assert_eq!(
//             AuthorizationResponse::builder()
//                 .redirect_uri("redirect".to_string())
//                 .presentation_submission("presentation_submission".to_string())
//                 .oid4vp_response_jwt("response".to_string())
//                 .build()
//                 .unwrap_err()
//                 .to_string(),
//             "`response` parameter can not be used with `vp_token` and `presentation_submission` parameters."
//         );
//     }
// }
