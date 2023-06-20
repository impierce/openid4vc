pub use dif_presentation_exchange::{
    evaluate_input, ClaimFormatDesignation, InputDescriptor, InputDescriptorMappingObject, PathNested,
    PresentationDefinition, PresentationSubmission,
};
use identity_credential::{credential::Jwt, presentation::JwtPresentation};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum VerifiablePresentation {
    JwtVp(JwtPresentation),
}
