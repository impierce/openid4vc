use crate::VpToken;
use anyhow::Result;
use dif_presentation_exchange::PresentationSubmission;
use futures::{executor::block_on, future::join_all};
use oid4vc_core::Decoder;
use oid4vci::VerifiableCredentialJwt;
use serde::{Deserialize, Serialize};

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

impl Oid4vpParams {
    pub async fn decode(&self, decoder: &Decoder) -> Result<Vec<VerifiableCredentialJwt>> {
        let vp_token: VpToken = match self {
            Oid4vpParams::Jwt { .. } => todo!(),
            Oid4vpParams::Params { vp_token, .. } => decoder.decode(vp_token.to_owned()).await?,
        };

        block_on(async move {
            join_all(
                vp_token
                    .verifiable_presentation()
                    .verifiable_credential
                    .iter()
                    .map(|vc| async { decoder.decode(vc.as_str().to_owned()).await }),
            )
            .await
            .into_iter()
            .collect()
        })
    }
}
