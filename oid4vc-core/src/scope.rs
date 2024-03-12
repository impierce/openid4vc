use anyhow::{anyhow, Result};
use derive_more::Display;
use serde::{de::Deserializer, Deserialize, Serialize};
use std::{slice::Iter, str::FromStr};

/// Set of scope values as specified in the
/// [OpenID Connect specification](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims).
#[derive(PartialEq, Debug, Clone, Default)]
pub struct Scope(Vec<ScopeValue>);

impl Scope {
    pub fn openid() -> Self {
        Scope(vec![ScopeValue::OpenId])
    }

    pub fn iter(&self) -> Iter<'_, ScopeValue> {
        self.0.iter()
    }
}

impl From<Vec<ScopeValue>> for Scope {
    fn from(values: Vec<ScopeValue>) -> Self {
        Scope(values)
    }
}

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.0.iter().map(|v| v.to_string()).collect::<Vec<String>>().join(" ");
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let values = s
            .split(' ')
            .map(ScopeValue::from_str)
            .collect::<Result<Vec<ScopeValue>>>()
            .map_err(|_| serde::de::Error::custom("Invalid scope value."))?;

        Ok(Scope(values))
    }
}

#[derive(Deserialize, Debug, PartialEq, Serialize, Clone, Display)]
#[serde(rename_all = "lowercase")]
pub enum ScopeValue {
    #[display(fmt = "openid")]
    OpenId,
    #[display(fmt = "profile")]
    Profile,
    #[display(fmt = "email")]
    Email,
    #[display(fmt = "address")]
    Address,
    #[display(fmt = "phone")]
    Phone,
}

impl std::str::FromStr for ScopeValue {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "openid" => Ok(ScopeValue::OpenId),
            "profile" => Ok(ScopeValue::Profile),
            "email" => Ok(ScopeValue::Email),
            "address" => Ok(ScopeValue::Address),
            "phone" => Ok(ScopeValue::Phone),
            _ => Err(anyhow!("Invalid scope value.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_value_deserialization() {
        assert_eq!(ScopeValue::OpenId, ScopeValue::from_str("openid").unwrap());
        assert_eq!(ScopeValue::Profile, ScopeValue::from_str("profile").unwrap());
        assert_eq!(ScopeValue::Email, ScopeValue::from_str("email").unwrap());
        assert_eq!(ScopeValue::Address, ScopeValue::from_str("address").unwrap());
        assert_eq!(ScopeValue::Phone, ScopeValue::from_str("phone").unwrap());
    }

    #[test]
    fn test_scope_value_serialization() {
        assert_eq!(r#"openid"#, ScopeValue::to_string(&ScopeValue::OpenId));
        assert_eq!(r#"profile"#, ScopeValue::to_string(&ScopeValue::Profile));
        assert_eq!(r#"email"#, ScopeValue::to_string(&ScopeValue::Email));
        assert_eq!(r#"address"#, ScopeValue::to_string(&ScopeValue::Address));
        assert_eq!(r#"phone"#, ScopeValue::to_string(&ScopeValue::Phone));
    }

    #[test]
    fn test_scope_deserialization() {
        assert_eq!(
            Scope(vec![
                ScopeValue::OpenId,
                ScopeValue::Profile,
                ScopeValue::Email,
                ScopeValue::Address,
                ScopeValue::Phone
            ]),
            serde_json::from_str(r#""openid profile email address phone""#).unwrap()
        );
    }

    #[test]
    fn test_scope_serialization() {
        assert_eq!(
            r#""openid profile email address phone""#,
            serde_json::to_string(&Scope::from(vec![
                ScopeValue::OpenId,
                ScopeValue::Profile,
                ScopeValue::Email,
                ScopeValue::Address,
                ScopeValue::Phone
            ]))
            .unwrap()
        );
    }
}
