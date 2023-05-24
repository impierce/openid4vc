use crate::builder_fn;
use anyhow::{anyhow, Result};
use getset::Getters;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum Openid4vpParams {
    Jwt {
        response: String,
    },
    Params {
        vp_token: String,
        presentation_submission: String,
    },
}

#[derive(Serialize, Default, Deserialize, Debug, Getters, PartialEq)]
#[skip_serializing_none]
pub struct Response {
    #[serde(skip)]
    #[getset(get = "pub")]
    redirect_uri: String,
    #[getset(get = "pub")]
    id_token: Option<String>,
    #[serde(flatten)]
    openid4vp_response: Option<Openid4vpParams>,
}

impl Response {
    pub fn builder() -> ResponseBuilder {
        ResponseBuilder::new()
    }
}

#[derive(Default)]
pub struct ResponseBuilder {
    redirect_uri: Option<String>,
    id_token: Option<String>,
    vp_token: Option<String>,
    presentation_submission: Option<String>,
    openid4vp_response_jwt: Option<String>,
}

impl ResponseBuilder {
    pub fn new() -> Self {
        ResponseBuilder::default()
    }

    pub fn build(&mut self) -> Result<Response> {
        let redirect_uri = self
            .redirect_uri
            .take()
            .ok_or(anyhow!("redirect_uri parameter is required."))?;

        let openid4vp_response = match (
            self.vp_token.take(),
            self.presentation_submission.take(),
            self.openid4vp_response_jwt.take(),
        ) {
            (Some(vp_token), Some(presentation_submission), None) => Ok(Some(Openid4vpParams::Params {
                vp_token,
                presentation_submission,
            })),
            (None, None, Some(response)) => Ok(Some(Openid4vpParams::Jwt { response })),
            (None, None, None) => Ok(None),
            _ => Err(anyhow!("Invalid combination of openid4vp response parameters.")),
        }?;

        Ok(Response {
            redirect_uri,
            id_token: self.id_token.take(),
            openid4vp_response,
        })
    }

    builder_fn!(redirect_uri, String);
    builder_fn!(id_token, String);
    builder_fn!(vp_token, String);
    builder_fn!(presentation_submission, String);
    builder_fn!(openid4vp_response_jwt, String);
}

// TODO: Improve tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openid4vp_response() {
        let response = Response::builder()
            .redirect_uri("redirect".to_string())
            .vp_token("vp_token".to_string())
            .presentation_submission("presentation_submission".to_string())
            .build()
            .unwrap();

        let response_string = serde_json::to_string(&response).unwrap();

        assert_eq!(
            Response {
                id_token: None,
                openid4vp_response: Some(Openid4vpParams::Params {
                    vp_token: "vp_token".to_string(),
                    presentation_submission: "presentation_submission".to_string(),
                }),
                ..Default::default()
            },
            serde_json::from_str(&response_string).unwrap()
        );
    }
}
