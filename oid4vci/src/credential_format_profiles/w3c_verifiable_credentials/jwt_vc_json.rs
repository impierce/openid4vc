use crate::{credential_definition::CredentialDefinition, credential_format};

credential_format!("jwt_vc_json", JwtVcJson, {
    credential_definition: CredentialDefinition
});
