use super::verifiable_presentation_jwt_builder::VerifiablePresentationJwtBuilder;
use getset::Getters;
use identity_kit::vc::{Party, Presentation, PresentationV2};
use oid4vc_core::{JsonObject, RFC7519Claims};
use serde::{Serialize, Serializer, ser::Error as _};

/// The presentation a [`VerifiablePresentationJwt`] carries.
#[derive(Clone, Debug, PartialEq)]
pub enum VerifiablePresentation {
    /// A VCDM 1.1 presentation of credential JWTs (`jwt_vc_json`), in the `vp` claim (VCDM 1.1 §6.3.1).
    V1(Presentation),
    /// A VCDM 2.0 presentation of enveloped credentials (`vc+sd-jwt`), which is the JWT payload itself
    /// (VC-JOSE-COSE §3.2).
    V2(PresentationV2),
}

impl VerifiablePresentation {
    /// The holder the presentation names, if any.
    pub fn holder(&self) -> Option<&Party> {
        match self {
            Self::V1(presentation) => presentation.holder.as_ref(),
            Self::V2(presentation) => presentation.holder.as_ref(),
        }
    }
}

impl From<Presentation> for VerifiablePresentation {
    fn from(presentation: Presentation) -> Self {
        Self::V1(presentation)
    }
}

impl From<PresentationV2> for VerifiablePresentation {
    fn from(presentation: PresentationV2) -> Self {
        Self::V2(presentation)
    }
}

/// The claims of a presentation JWT, which serialize as the JWT payload: the presentation (in the `vp` claim, or as
/// the payload itself for VCDM 2.0), the registered claims and the `nonce`.
#[derive(Clone, Debug, Getters, PartialEq)]
pub struct VerifiablePresentationJwt {
    #[getset(get = "pub")]
    pub(super) rfc7519_claims: RFC7519Claims,
    #[getset(get = "pub")]
    pub(super) verifiable_presentation: VerifiablePresentation,
    #[getset(get = "pub")]
    pub(super) nonce: Option<String>,
}

impl VerifiablePresentationJwt {
    pub fn builder() -> VerifiablePresentationJwtBuilder {
        VerifiablePresentationJwtBuilder::new()
    }
}

impl Serialize for VerifiablePresentationJwt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let presentation = match &self.verifiable_presentation {
            VerifiablePresentation::V1(presentation) => {
                serde_json::to_value(presentation.to_jwt_claims().map_err(S::Error::custom)?)
            }
            VerifiablePresentation::V2(presentation) => serde_json::to_value(presentation),
        };
        let mut claims = into_object(presentation).map_err(S::Error::custom)?;
        // The registered claims set here agree with what the presentation maps to them (`iss` with the holder).
        claims.extend(into_object(serde_json::to_value(&self.rfc7519_claims)).map_err(S::Error::custom)?);
        if let Some(nonce) = &self.nonce {
            claims.insert("nonce".to_owned(), nonce.clone().into());
        }
        claims.serialize(serializer)
    }
}

fn into_object(value: serde_json::Result<serde_json::Value>) -> Result<JsonObject, String> {
    match value.map_err(|e| e.to_string())? {
        serde_json::Value::Object(object) => Ok(object),
        _ => Err("not a JSON object".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_kit::{
        did::Did,
        vc::{EnvelopedVc, Jwt},
    };
    use serde_json::json;

    const HOLDER: &str = "did:example:ebfeb1f712ebc6f1c276e12ec21";
    const VERIFIER: &str = "did:example:4a57546973436f6f6c4a4a57573";
    // RFC 8037 Appendix A.4, standing in for a credential JWT.
    const CREDENTIAL: &str = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
        hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

    fn credential() -> Jwt {
        Jwt::new(CREDENTIAL).unwrap()
    }

    fn holder() -> Did {
        Did::parse(HOLDER).unwrap()
    }

    fn builder() -> VerifiablePresentationJwtBuilder {
        VerifiablePresentationJwt::builder()
            .iss(HOLDER.to_string())
            .sub(HOLDER.to_string())
            .aud(VERIFIER.to_string())
            .iat(1_700_000_000)
            .exp(1_700_000_600)
            .nonce("343s$FSFDa-".to_string())
    }

    #[test]
    fn vcdm_1_1_presentation_is_the_vp_claim() {
        let presentation = Presentation::new().with_holder(holder()).with_credential(credential());
        let claims = serde_json::to_value(builder().verifiable_presentation(presentation).build().unwrap()).unwrap();

        assert_eq!(
            claims,
            json!({
                "iss": HOLDER,
                "vp": {
                    "@context": "https://www.w3.org/2018/credentials/v1",
                    "type": "VerifiablePresentation",
                    "verifiableCredential": [CREDENTIAL],
                },
                "sub": HOLDER,
                "aud": VERIFIER,
                "exp": 1_700_000_600,
                "iat": 1_700_000_000,
                "nonce": "343s$FSFDa-",
            })
        );
    }

    #[test]
    fn vcdm_2_0_presentation_is_the_payload() {
        let presentation = PresentationV2::new()
            .with_holder(holder())
            .with_credential(EnvelopedVc::from_jwt(&credential()));
        let claims = serde_json::to_value(builder().verifiable_presentation(presentation).build().unwrap()).unwrap();

        assert_eq!(claims["@context"], "https://www.w3.org/ns/credentials/v2");
        assert_eq!(claims["holder"], HOLDER);
        assert_eq!(claims["iss"], HOLDER);
        assert_eq!(
            claims["verifiableCredential"][0]["id"],
            format!("data:application/vc+jwt,{CREDENTIAL}")
        );
        assert_eq!(claims["aud"], VERIFIER);
        assert_eq!(claims["nonce"], "343s$FSFDa-");
        assert!(claims.get("vp").is_none());
    }

    #[test]
    fn holder_must_be_iss() {
        let presentation = Presentation::new().with_holder(Did::parse("did:example:other").unwrap());
        let error = builder().verifiable_presentation(presentation).build().unwrap_err();
        assert_eq!(
            error.to_string(),
            "the holder of the presentation must be the iss claim"
        );
    }

    #[test]
    fn presentation_is_required() {
        let error = builder().build().unwrap_err();
        assert_eq!(error.to_string(), "verifiable_presentation is required");
    }
}
