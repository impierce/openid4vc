// use siopv2::{subject::Subjects, validator::Validators, Provider};

// pub struct ProviderManager {
//     provider: Provider,
// }

// impl ProviderManager {
//     pub fn new(provider: Provider) -> Self {
//         Self { provider }
//     }

//     /// TODO: Change to `read_request` or something similar.
//     /// Takes a [`RequestUrl`] and returns a [`AuthorizationRequest`]. The [`RequestUrl`] can either be a [`AuthorizationRequest`] or a
//     /// request by value. If the [`RequestUrl`] is a request by value, the request is decoded by the [`Subject`] of the [`Provider`].
//     /// If the request is valid, the request is returned.
//     pub async fn validate_request(&self, request: RequestUrl) -> Result<AuthorizationRequest> {
//         self.provider.validate_request(request).await
//     }

//     pub fn set_signer_subject(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
//         let signer_subject = self
//             .provider
//             .subjects
//             .iter()
//             .find(|&subject| {
//                 subject
//                     .identifier()
//                     .map(|did| subject_syntax_type == DidMethod::from(did).into())
//                     .unwrap_or(false)
//             })
//             .ok_or_else(|| anyhow::anyhow!("No subject with the given syntax type found."))?;
//         self.provider.signer_subject = signer_subject.clone();
//         Ok(())
//     }
// }

// // TODO: consider moving this functionality to the oid4vc-agent crate.
// pub fn matching_subject_syntax_types(
//     &self,
//     authorization_request: &AuthorizationRequest,
// ) -> Option<Vec<SubjectSyntaxType>> {
//     let supported = self.subject_syntax_types_supported().ok()?;
//     let supported_types = authorization_request
//         .subject_syntax_types_supported()
//         .map_or(Vec::new(), |types| {
//             types.iter().filter(|sst| supported.contains(sst)).collect()
//         });
//     (!supported_types.is_empty()).then_some(supported_types.iter().map(|&sst| sst.clone()).collect())
// }

// pub fn set_active_subject(&mut self, subject_syntax_type: SubjectSyntaxType) -> Result<()> {
//     let subject = self
//         .subjects
//         .iter()
//         .find(|&subject| {
//             subject
//                 .identifier()
//                 .map(|did| subject_syntax_type == DidMethod::from(did).into())
//                 .unwrap_or(false)
//         })
//         .ok_or_else(|| anyhow::anyhow!("No subject with the given syntax type found."))?;
//     self.subject = subject.clone();
//     Ok(())
// }

// pub fn subject_syntax_types_supported(&self) -> Result<Vec<SubjectSyntaxType>> {
//     self.subjects
//         .iter()
//         .map(|subject| subject.identifier().map(|did| DidMethod::from(did).into()))
//         .collect()
// }

// // TODO: consider moving this functionality to the oid4vc-agent crate.
// pub fn matching_subject_syntax_types(
//     &self,
//     authorization_request: &AuthorizationRequest,
// ) -> Option<Vec<SubjectSyntaxType>> {
//     let supported = self.subject_syntax_types_supported().ok()?;
//     let supported_types = authorization_request
//         .subject_syntax_types_supported()
//         .map_or(Vec::new(), |types| {
//             types.iter().filter(|sst| supported.contains(sst)).collect()
//         });
//     (!supported_types.is_empty()).then_some(supported_types.iter().map(|&sst| sst.clone()).collect())
// }
