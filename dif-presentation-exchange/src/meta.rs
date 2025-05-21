use crate::presentation_definition::MetaTypes;
use serde_json::Value;
use std::collections::HashMap;
use validator::ValidationError;

pub const W3C_FORMAT: [&str; 2] = ["ldp_vc", "jwt_vc_json"];
pub const SDJWT_FORMAT: [&str; 1] = ["dc+sd-jwt"];
pub const MSO_MDOC: [&str; 1] = ["mso_mdoc"];
pub const ALL_SUPPORTED_FORMATS: [&str; 4] = ["ldp_vc", "jwt_vc_json", "dc+sd-jwt", "mso_mdoc"];

pub fn validate_format(format: &str) -> Result<(), ValidationError> {
    if ALL_SUPPORTED_FORMATS.contains(&format) {
        Ok(())
    } else {
        Err(ValidationError::new("unsupported_credential_format")
            .with_message(format!("Unsupported credential format: {}", format).into()))
    }
}

#[derive(Debug)]
pub struct MetaContext<'a> {
    pub format: &'a str,
}

pub fn validate_meta(meta: &Option<MetaTypes>, ctx: &MetaContext) -> Result<(), ValidationError> {
    let Some(meta_value) = meta else {
        return Ok(()); // since meta is considered an OPTIONAL field. Returns OK if it is none.
    };

    match meta_value {
        MetaTypes::W3CFormatMeta { type_values } => {
            if !W3C_FORMAT.contains(&ctx.format) {
                return Err(ValidationError::new("incorrect_meta_format")
                    .with_message(format!("jwt_vc_json is incompatible with format: {}", ctx.format).into()));
            }
            validate_w3c_type_values(type_values)
        }
        MetaTypes::SdJwtMeta { vct_values } => {
            if !SDJWT_FORMAT.contains(&ctx.format) {
                return Err(ValidationError::new("incorrect_meta_format")
                    .with_message(format!("SdJwtMeta is not compatible with format: {}", ctx.format).into()));
            }
            validate_sd_jwt_vct_values(vct_values)
        }
        MetaTypes::MsoMdocMeta { doctype_value } => {
            if !MSO_MDOC.contains(&ctx.format) {
                return Err(ValidationError::new("incorrect_meta_format")
                    .with_message(format!("MsoMdocMeta is not compatible with format: {}", ctx.format).into()));
            }
            validate_mso_mdoc_doctype(doctype_value)
        }
    }
}

fn validate_w3c_type_values(type_values: &[Vec<String>]) -> Result<(), ValidationError> {
    if type_values.is_empty() {
        return Err(ValidationError::new("invalid_type_values").with_message("type_values cannot be empty".into()));
    }

    for (i, inner_array) in type_values.iter().enumerate() {
        if inner_array.is_empty() {
            return Err(ValidationError::new("invalid_type_values")
                .with_message(format!("type_values[{}] cannot be empty", i).into()));
        }

        for (j, value) in inner_array.iter().enumerate() {
            if value.is_empty() {
                return Err(ValidationError::new("invalid_type_values")
                    .with_message(format!("type_values[{}][{}] cannot be empty", i, j).into()));
            }
        }
    }

    Ok(())
}

fn validate_sd_jwt_vct_values(vct_values: &[String]) -> Result<(), ValidationError> {
    if vct_values.is_empty() {
        return Err(ValidationError::new("invalid_vct_values").with_message("vct_values cannot be empty".into()));
    }

    for (i, value) in vct_values.iter().enumerate() {
        if value.is_empty() {
            return Err(ValidationError::new("invalid_vct_values")
                .with_message(format!("vct_values[{}] cannot be empty", i).into()));
        }
    }

    Ok(())
}

fn validate_mso_mdoc_doctype(doctype_value: &str) -> Result<(), ValidationError> {
    if doctype_value.is_empty() {
        return Err(ValidationError::new("invalid_doctype_value").with_message("doctype_value cannot be empty".into()));
    }

    Ok(())
}

pub fn validate_w3c_meta(meta_value: &Value) -> Result<(), ValidationError> {
    let meta: HashMap<String, Value> = serde_json::from_value(meta_value.clone())
        .map_err(|_| ValidationError::new("invalid_meta_format").with_message("Metadata Format Invalid".into()))?;

    let type_values = meta.get("type_values").ok_or_else(|| {
        ValidationError::new("missing_type_values").with_message("Missing required field: 'type_values'".into())
    })?;

    let type_values_array = match type_values {
        Value::Array(arr) => arr,
        _ => {
            return Err(
                ValidationError::new("invalid_type_values").with_message("Field 'type_values' must be an array".into())
            );
        }
    };

    if type_values_array.is_empty() {
        return Err(
            ValidationError::new("invalid_type_values").with_message("Field 'type_values' cannot be empty".into())
        );
    }

    for (i, value) in type_values_array.iter().enumerate() {
        let inner_array = match value {
            Value::Array(arr) => arr,
            _ => {
                return Err(ValidationError::new("invalid_type_values")
                    .with_message(format!("Field 'type_values[{}]' must be an array", i).into()))
            }
        };
        if inner_array.is_empty() {
            return Err(ValidationError::new("invalid_type_values")
                .with_message(format!("Field 'type_values[{}]' cannot be empty", i).into()));
        }

        for (j, type_value) in inner_array.iter().enumerate() {
            match type_value {
                Value::String(s) if !s.is_empty() => {}
                Value::String(_) => {
                    return Err(ValidationError::new("invalid_type_values")
                        .with_message(format!("type_values[{}][{}] cannot be empty", i, j).into()))
                }
                _ => {
                    return Err(ValidationError::new("invalid_type_values")
                        .with_message(format!("Field 'type_values[{}][{}]' must be a string", i, j).into()))
                }
            };
        }
    }

    Ok(())
}

pub fn validate_sd_jwt_meta(meta_value: &Value) -> Result<(), ValidationError> {
    let meta: HashMap<String, Value> = serde_json::from_value(meta_value.clone())
        .map_err(|_| ValidationError::new("invalid_meta_format").with_message("Metadata Format Invalid".into()))?;

    let vct_values = meta.get("vct_values").ok_or_else(|| {
        ValidationError::new("invalid_meta_format").with_message("Missing required field: 'vct_values'".into())
    })?;

    let vct_values_array = match vct_values {
        Value::Array(arr) => arr,
        _ => {
            return Err(ValidationError::new("invalid_vct_values_format")
                .with_message("Field 'vct_values' must be an array".into()))
        }
    };

    if vct_values_array.is_empty() {
        return Err(ValidationError::new("invalid_vct_values").with_message("vct_values cannot be empty".into()));
    }

    for (i, value) in vct_values_array.iter().enumerate() {
        match value {
            Value::String(s) if !s.is_empty() => {}
            Value::String(_) => {
                return Err(ValidationError::new("invalid_vct_values")
                    .with_message(format!("Field 'vct_values[{}]' cannot be empty", i).into()))
            }
            _ => {
                return Err(ValidationError::new("invalid_vct_values")
                    .with_message(format!("Field 'vct_values[{}]' must be a string", i).into()))
            }
        };
    }

    Ok(())
}

pub struct W3CMeta {
    pub type_values: Vec<Vec<String>>,
}
pub struct SDJwtMeta {
    pub vct_values: Vec<String>,
}
pub struct MSOmdocMeta {
    pub doctype_value: String,
}
