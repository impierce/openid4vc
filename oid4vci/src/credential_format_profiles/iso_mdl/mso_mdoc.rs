use crate::credential_format;

credential_format!("mso_mdoc", MsoMdoc, MsoMdocParameters, MsoMdocCredential, {
    doctype: String
});
