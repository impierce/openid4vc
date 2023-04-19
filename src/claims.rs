use crate::scope::{Scope, ScopeValue};
use merge::Merge;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;

#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ClaimRequests {
    pub user_claims: Option<StandardClaims>,
    pub id_token: Option<StandardClaims>,
}

/// an enum to represent a claim. It can be a value, a request or the default value.
#[derive(Debug, PartialEq, Clone, Serialize, Default, Deserialize)]
#[serde(untagged)]
pub enum Claim<T> {
    #[default]
    Default,
    Value(T),
    Request(IndividualClaimRequest<T>),
}

/// An individual claim request as defined in [OpenID Connect Core 1.0, section 5.5.1](https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests).
#[skip_serializing_none]
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndividualClaimRequest<T> {
    pub essential: Option<bool>,
    pub value: Option<T>,
    pub values: Option<Vec<T>>,
}

/// Standard claims as defined in [OpenID Connect Core 1.0, section 5.1](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Merge, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StandardClaims {
    // Profile scope
    #[serde(deserialize_with = "parse_optional_claim")]
    pub name: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub family_name: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub given_name: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub middle_name: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub nickname: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub preferred_username: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub profile: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub picture: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub website: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub gender: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub birthdate: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub zoneinfo: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub locale: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub updated_at: Option<Claim<i64>>,
    // Email scope
    #[serde(deserialize_with = "parse_optional_claim")]
    pub email: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub email_verified: Option<Claim<bool>>,
    // Address scope
    #[serde(deserialize_with = "parse_optional_claim")]
    pub address: Option<Claim<Address>>,
    // Phone scope
    #[serde(deserialize_with = "parse_optional_claim")]
    pub phone_number: Option<Claim<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub phone_number_verified: Option<Claim<bool>>,
}

/// A helper function to deserialize a claim. If the claim is not present, it will be deserialized as a `None` value.
/// If the claim is present, but the value is `null`, it will be deserialized as `Some(Claim::Default)`.
fn parse_optional_claim<'de, D, T>(d: D) -> Result<Option<Claim<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    Deserialize::deserialize(d).map(|x: Option<_>| x.unwrap_or(Some(Claim::default())))
}

// TODO: Check whether claims from a scope are essential or not.
impl From<&Scope> for StandardClaims {
    fn from(value: &Scope) -> Self {
        value
            .iter()
            .map(|scope_value| match scope_value {
                ScopeValue::Profile => StandardClaims {
                    name: Some(Claim::default()),
                    family_name: Some(Claim::default()),
                    given_name: Some(Claim::default()),
                    middle_name: Some(Claim::default()),
                    nickname: Some(Claim::default()),
                    preferred_username: Some(Claim::default()),
                    profile: Some(Claim::default()),
                    picture: Some(Claim::default()),
                    website: Some(Claim::default()),
                    gender: Some(Claim::default()),
                    birthdate: Some(Claim::default()),
                    zoneinfo: Some(Claim::default()),
                    locale: Some(Claim::default()),
                    updated_at: Some(Claim::default()),
                    ..Default::default()
                },
                ScopeValue::Email => StandardClaims {
                    email: Some(Claim::default()),
                    email_verified: Some(Claim::default()),
                    ..Default::default()
                },
                ScopeValue::Phone => StandardClaims {
                    phone_number: Some(Claim::default()),
                    phone_number_verified: Some(Claim::default()),
                    ..Default::default()
                },
                _ => Default::default(),
            })
            .reduce(|mut a, b| {
                a.merge(b);
                a
            })
            .unwrap()
    }
}

#[skip_serializing_none]
#[derive(Debug, PartialEq, Clone, Serialize, Default, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct Address {
    pub formatted: Option<Claim<String>>,
    pub street_address: Option<Claim<String>>,
    pub locality: Option<Claim<String>>,
    pub region: Option<Claim<String>>,
    pub postal_code: Option<Claim<String>>,
    pub country: Option<Claim<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{MemoryStorage, Storage};
    use lazy_static::lazy_static;
    use serde_json::{json, Value};

    lazy_static! {
        pub static ref USER_CLAIMS: Value = json!(
            {
                "name": "Jane Doe",
                "given_name": "Jane",
                "family_name": "Doe",
                "middle_name": "Middle",
                "nickname": "JD",
                "preferred_username": "j.doe",
                "profile": "https://example.com/janedoe",
                "picture": "https://example.com/janedoe/me.jpg",
                "website": "https://example.com",
                "email": "jane.doe@example.com",
                "updated_at": 1311280970,
                "address": {
                    "formatted": "100 Universal City Plaza\nHollywood, CA 91608",
                    "street_address": "100 Universal City Plaza",
                    "locality": "Hollywood",
                    "region": "CA",
                    "postal_code": "91608",
                    "country": "US"
                }
            }
        );
    }

    #[test]
    fn test_deserialize_user_claims() {
        let user_claims: StandardClaims = serde_json::from_value(USER_CLAIMS.clone()).unwrap();
        assert_eq!(user_claims.name, Some(Claim::Value("Jane Doe".to_string())));
        assert_eq!(user_claims.given_name, Some(Claim::Value("Jane".to_string())));
        assert_eq!(user_claims.family_name, Some(Claim::Value("Doe".to_string())));
        assert_eq!(user_claims.middle_name, Some(Claim::Value("Middle".to_string())));
        assert_eq!(user_claims.nickname, Some(Claim::Value("JD".to_string())));
        assert_eq!(user_claims.preferred_username, Some(Claim::Value("j.doe".to_string())));
        assert_eq!(
            user_claims.profile,
            Some(Claim::Value("https://example.com/janedoe".to_string()))
        );
        assert_eq!(
            user_claims.picture,
            Some(Claim::Value("https://example.com/janedoe/me.jpg".to_string()))
        );
        assert_eq!(
            user_claims.website,
            Some(Claim::Value("https://example.com".to_string()))
        );
        assert_eq!(
            user_claims.email,
            Some(Claim::Value("jane.doe@example.com".to_string()))
        );
        assert_eq!(user_claims.updated_at, Some(Claim::Value(1311280970)));
        assert_eq!(
            user_claims.address,
            Some(Claim::Value(Address {
                formatted: Some(Claim::Value(
                    "100 Universal City Plaza\nHollywood, CA 91608".to_string()
                )),
                street_address: Some(Claim::Value("100 Universal City Plaza".to_string())),
                locality: Some(Claim::Value("Hollywood".to_string())),
                region: Some(Claim::Value("CA".to_string())),
                postal_code: Some(Claim::Value("91608".to_string())),
                country: Some(Claim::Value("US".to_string())),
            }))
        );
    }

    #[test]
    fn test_request_claims() {
        // Store the user claims in the storage.
        let storage = MemoryStorage::new(serde_json::from_value::<StandardClaims>(USER_CLAIMS.clone()).unwrap());

        // Initialize a set of request claims.
        let request_claims = ClaimRequests {
            id_token: Some(StandardClaims {
                name: Some(Claim::default()),
                given_name: Some(Claim::Request(IndividualClaimRequest {
                    essential: Some(false),
                    ..Default::default()
                })),
                family_name: Some(Claim::Request(IndividualClaimRequest {
                    value: Some("Doe".to_string()),
                    ..Default::default()
                })),
                middle_name: Some(Claim::Request(IndividualClaimRequest {
                    values: Some(vec!["Doe".to_string(), "Done".to_string()]),
                    ..Default::default()
                })),
                nickname: Some(Claim::Request(IndividualClaimRequest {
                    essential: Some(false),
                    value: Some("JD".to_string()),
                    ..Default::default()
                })),
                updated_at: Some(Claim::Request(IndividualClaimRequest {
                    essential: Some(false),
                    values: Some(vec![1311280970, 1311280971]),
                    ..Default::default()
                })),
                address: Some(Claim::Request(IndividualClaimRequest {
                    essential: Some(false),
                    value: Some(Address {
                        formatted: Some(Claim::Request(IndividualClaimRequest {
                            essential: Some(false),
                            ..Default::default()
                        })),
                        street_address: Some(Claim::Request(IndividualClaimRequest {
                            value: Some("100 Universal City Plaza".to_string()),
                            ..Default::default()
                        })),
                        locality: Some(Claim::Request(IndividualClaimRequest {
                            values: Some(vec!["Hollywood".to_string(), "Amsterdam".to_string()]),
                            ..Default::default()
                        })),
                        region: Some(Claim::Request(IndividualClaimRequest {
                            essential: Some(false),
                            value: Some("CA".to_string()),
                            ..Default::default()
                        })),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
                ..Default::default()
            }),
            user_claims: None,
        };

        // Fetch a selection of the user claims (based on the request claims) from the storage.
        let response_claims = storage.fetch_claims(&request_claims.id_token.unwrap());

        assert_eq!(response_claims.name, Some(Claim::Value("Jane Doe".to_string())));
        assert_eq!(response_claims.given_name, Some(Claim::Value("Jane".to_string())));
        assert_eq!(response_claims.family_name, Some(Claim::Value("Doe".to_string())));
        assert_eq!(response_claims.middle_name, Some(Claim::Value("Middle".to_string())));
        assert_eq!(response_claims.nickname, Some(Claim::Value("JD".to_string())));
        assert_eq!(response_claims.updated_at, Some(Claim::Value(1311280970)));
        assert_eq!(
            response_claims.address,
            Some(Claim::Value(Address {
                formatted: Some(Claim::Value(
                    "100 Universal City Plaza\nHollywood, CA 91608".to_string()
                )),
                street_address: Some(Claim::Value("100 Universal City Plaza".to_string())),
                locality: Some(Claim::Value("Hollywood".to_string())),
                region: Some(Claim::Value("CA".to_string())),
                postal_code: Some(Claim::Value("91608".to_string())),
                country: Some(Claim::Value("US".to_string())),
            }))
        );
    }

    #[test]
    fn test_from_scope() {
        // Assert that the combination of scopes is correctly mapped to the standard claims
        let scope = Scope::from(vec![ScopeValue::OpenId, ScopeValue::Email, ScopeValue::Phone]);
        assert_eq!(
            StandardClaims::from(&scope),
            StandardClaims {
                email: Some(Claim::default()),
                email_verified: Some(Claim::default()),
                phone_number: Some(Claim::default()),
                phone_number_verified: Some(Claim::default()),
                ..Default::default()
            }
        );
    }
}
