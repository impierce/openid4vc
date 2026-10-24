use crate::credential_format;

credential_format!("dc+sd-jwt", DcSdJwt, DcSdJwtParameters, DcSdJwtCredential, {
    vct: String
});
