use crate::{credential_definition::CredentialDefinition, credential_format};

credential_format!("jwt_vc_json", JwtVcJson, {
    credential_definition: CredentialDefinition,
    order: Option<String>
});

credential_format!("custom_format", CustomFormat, {
    field: String,
    dsfbfgsb: Option<bool>
});

#[test]
fn test() {
    
}