use crate::{
    jwt, sign::Signers, subject_syntax_type::DidMethod, validator::Validators, AuthorizationRequest,
    AuthorizationResponse, IdToken, SubjectSyntaxType,
};
use anyhow::{anyhow, Result};
use std::str::FromStr;

pub struct RelyingParty {
    // TODO: Need to change this to active_sign-method or other solution. Probably move this abstraction layer to the
    // oid-agent crate.
    pub signers: Signers,
    pub validators: Validators,
}

impl RelyingParty {
    // TODO: Use RelyingPartyBuilder instead.
    pub fn new(signers: Signers, validators: Validators) -> Self {
        RelyingParty { signers, validators }
    }

    pub async fn encode(&self, signer_type: SubjectSyntaxType, request: &AuthorizationRequest) -> Result<String> {
        jwt::encode(
            self.signers
                .get(&signer_type)
                .ok_or_else(|| anyhow!("No signer found with type: {:?}", signer_type))?
                .clone(),
            request,
        )
        .await
    }

    /// Validates a [`AuthorizationResponse`] by decoding the header of the id_token, fetching the public key corresponding to
    /// the key identifier and finally decoding the id_token using the public key and by validating the signature.
    // TODO: Validate the claims in the id_token as described here:
    // https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#name-self-issued-id-token-valida
    pub async fn validate_response(&self, response: &AuthorizationResponse) -> Result<IdToken> {
        let token = response
            .id_token()
            .to_owned()
            .ok_or(anyhow::anyhow!("No id_token parameter in response"))?;
        // TODO: what if the kid does not belong to a DID?
        let (kid, algorithm) = jwt::extract_header(&token)?;
        let did_method = DidMethod::from(did_url::DID::from_str(&kid)?);

        let validator = self.validators.0.get(&did_method.into()).unwrap();
        let public_key = validator.public_key(&kid).await?;
        let id_token: IdToken = jwt::decode(&token, public_key, algorithm)?;
        Ok(id_token)
    }
}
