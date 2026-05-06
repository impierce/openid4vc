use super::dcql_query::{Format, MetaTypes};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetaError {
    #[error("Meta type {0:?} is not compatible with format {1:?}")]
    IncompatibleMetaFormat(MetaTypes, Format),
    #[error("type_values cannot be empty")]
    EmptyTypeValues,
    #[error("type_values[{0}] cannot be empty")]
    EmptyTypeValuesArray(usize),
    #[error("type_values[{0}][{1}] cannot be empty")]
    EmptyTypeValuesString(usize, usize),
    #[error("vct_values cannot be empty")]
    EmptyVctValues,
    #[error("vct_values[{0}] cannot be empty")]
    EmptyVctValuesString(usize),
    #[error("doctype_value cannot be empty")]
    EmptyDoctypeValue,
}

#[derive(Debug)]
pub struct MetaContext<'a> {
    pub format: &'a Format,
}

pub fn validate_meta(meta: &MetaTypes, ctx: &MetaContext) -> Result<(), MetaError> {
    match (&ctx.format, meta) {
        (Format::LdpVc, MetaTypes::W3CFormatMeta { type_values }) => validate_w3c_type_values(type_values),
        (Format::JwtVcJson, MetaTypes::W3CFormatMeta { type_values }) => validate_w3c_type_values(type_values),
        (Format::VcSdJwt, MetaTypes::W3CFormatMeta { type_values }) => validate_w3c_type_values(type_values),
        (Format::DcSdJwt, MetaTypes::SdJwtMeta { vct_values }) => validate_sd_jwt_vct_values(vct_values),
        (Format::MsoMdoc, MetaTypes::MsoMdocMeta { doctype_value }) => validate_mso_mdoc_doctype(doctype_value),
        (format, meta) => Err(MetaError::IncompatibleMetaFormat(meta.clone(), (*format).clone())),
    }
}

fn validate_w3c_type_values(type_values: &[Vec<String>]) -> Result<(), MetaError> {
    if type_values.is_empty() {
        return Err(MetaError::EmptyTypeValues);
    }

    for (i, inner_array) in type_values.iter().enumerate() {
        if inner_array.is_empty() {
            return Err(MetaError::EmptyTypeValuesArray(i));
        }

        for (j, value) in inner_array.iter().enumerate() {
            if value.is_empty() {
                return Err(MetaError::EmptyTypeValuesString(i, j));
            }
        }
    }

    Ok(())
}

fn validate_sd_jwt_vct_values(vct_values: &[String]) -> Result<(), MetaError> {
    if vct_values.is_empty() {
        return Err(MetaError::EmptyVctValues);
    }

    for (i, value) in vct_values.iter().enumerate() {
        if value.is_empty() {
            return Err(MetaError::EmptyVctValuesString(i));
        }
    }

    Ok(())
}

fn validate_mso_mdoc_doctype(doctype_value: &str) -> Result<(), MetaError> {
    if doctype_value.is_empty() {
        return Err(MetaError::EmptyDoctypeValue);
    }

    Ok(())
}
