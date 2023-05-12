use crate::scope::{Scope, ScopeValue};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;

/// Functions as the `claims` parameter inside a [`crate::SiopRequest`].
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ClaimRequests {
    pub user_claims: Option<StandardClaims<IndividualClaimRequest>>,
    pub id_token: Option<StandardClaims<IndividualClaimRequest>>,
}

/// The Claim trait has multiple associated types: String, Integer, Boolean, and Address. Each associated type specifies
/// a ValueType, which is a type that the corresponding claim can store.
/// The Address associated type has a more specific ValueType, which is defined as an Address type parameterized by the
/// String associated type of the Claim type being defined.
pub trait Claim: Default + Clone + for<'de> Deserialize<'de> {
    type ValueType;
    type String: Claim<ValueType = String> + Serialize;
    type Integer: Claim<ValueType = i64> + Serialize;
    type Boolean: Claim<ValueType = bool> + Serialize;
    type Address: Claim<ValueType = Address<Self::String>> + Serialize;
}

// Represents an actual claim value that can be send to the [`crate::RelyingParty`] via an [`IdToken`].
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ClaimValue<T = ()>(pub T);
impl<T: Default + Clone + for<'de> Deserialize<'de>> Claim for ClaimValue<T> {
    type ValueType = T;
    type String = ClaimValue<String>;
    type Integer = ClaimValue<i64>;
    type Boolean = ClaimValue<bool>;
    type Address = ClaimValue<Address<Self::String>>;
}

/// An individual claim request as defined in [OpenID Connect Core 1.0, section 5.5.1](https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests).
/// Individual claims can be requested by simply some key with a `null` value, or by using the `essential`, `value`,
/// and `values` fields. Additional information about the requested claim MAY be added to the claim request. This
/// addition allows for more flexibility in requesting for claims that is outside the scope of the OpenID core
/// specification.
/// # Example
/// ```
/// # use siopv2::claims::{StandardClaims, IndividualClaimRequest};
/// # use serde_json::json;
/// let claims = serde_json::from_value::<StandardClaims<IndividualClaimRequest>>(json!({
///     "name": null,
///     "family_name": {
///       "essential": true
///     },
///     "locale": {
///         "essential": true,
///         "value": "en-US"
///     },
///     "birthdate": {
///         "essential": true,
///         "between": [
///             "1970-01-01",
///             "2000-01-01"
///         ]
/// }}));
/// assert!(claims.is_ok());
/// dbg!(&claims);
/// ```
#[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct IndividualClaimRequest<T = ()>(Option<IndividualClaimRequestObject<T>>);
impl<T: Default + Clone + for<'de> Deserialize<'de>> Claim for IndividualClaimRequest<T> {
    type ValueType = T;
    type String = IndividualClaimRequest<String>;
    type Integer = IndividualClaimRequest<i64>;
    type Boolean = IndividualClaimRequest<bool>;
    type Address = IndividualClaimRequest<Address<Self::String>>;
}

impl<T> IndividualClaimRequest<T> {
    pub fn from_request_object(request: IndividualClaimRequestObject<T>) -> Self {
        IndividualClaimRequest(Some(request))
    }
}

#[skip_serializing_none]
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndividualClaimRequestObject<T> {
    // By requesting Claims as Essential Claims, the RP indicates to the End-User that releasing these Claims will
    // ensure a smooth authorization for the specific task requested by the End-User.
    pub essential: Option<bool>,
    // Requests that the Claim be returned with a particular value.
    pub value: Option<T>,
    // Requests that the Claim be returned with one of a set of values, with the values appearing in order of
    // preference.
    pub values: Option<Vec<T>>,
    // Other members MAY be defined to provide additional information about the requested Claims. Any members used that
    // are not understood MUST be ignored.
    #[serde(flatten, deserialize_with = "parse_other")]
    pub other: Option<serde_json::Value>,
}

// When a struct has fields of type `Option<serde_json::Value>`, by default these fields are deserialized as
// `Some(Object {})` instead of None when the corresponding values are missing.
// The `parse_other()` helper function ensures that these fields are deserialized as `None` when no value is present.
fn parse_other<'de, D>(deserializer: D) -> Result<Option<serde_json::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Object(object) if object.is_empty() => Ok(None),
        _ => Ok(Some(value)),
    }
}

/// This struct represents the standard claims as defined in the
/// [OpenID Connect Core 1.0 Specification](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
/// specification. It can be used either for requesting claims using [`IndividualClaimRequest`]'s in the `claims`
/// parameter of a [`crate::SiopRequest`], or for returning actual [`ClaimValue`]'s in an [`crate::IdToken`].
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StandardClaims<C>
where
    C: Claim,
{
    #[serde(deserialize_with = "parse_optional_claim")]
    pub name: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub family_name: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub given_name: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub middle_name: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub nickname: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub preferred_username: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub profile: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub picture: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub website: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub gender: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub birthdate: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub zoneinfo: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub locale: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub updated_at: Option<C::Integer>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub email: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub email_verified: Option<C::Boolean>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub address: Option<C::Address>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub phone_number: Option<C::String>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub phone_number_verified: Option<C::Boolean>,
}

/// A helper function to deserialize a claim. If the claim is not present, it will be deserialized as a `None` value.
/// If the claim is present, but the value is `null`, it will be deserialized as `Some(Claim::default())`.
fn parse_optional_claim<'de, D, T, C>(d: D) -> Result<Option<C>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
    C: Claim<ValueType = T>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| x.unwrap_or(Some(C::default())))
}

impl<C> StandardClaims<C>
where
    C: Claim,
{
    /// Takes another `StandardClaims<C>` and takes it's values for every missing `None` valued field.
    pub fn merge(&mut self, other: Self) {
        macro_rules! merge_if_none {
            ($($field: ident),+ $(,)?) => {
                $(
                    if self.$field.is_none() {
                        self.$field = other.$field.clone();
                    }
                )+
            };
        }

        merge_if_none!(
            name,
            family_name,
            given_name,
            middle_name,
            nickname,
            preferred_username,
            profile,
            picture,
            website,
            gender,
            birthdate,
            zoneinfo,
            locale,
            updated_at,
            email,
            email_verified,
            address,
            phone_number,
            phone_number_verified
        );
    }
}

#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Address<S>
where
    S: Claim<ValueType = String>,
{
    #[serde(deserialize_with = "parse_optional_claim")]
    pub formatted: Option<S>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub street_address: Option<S>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub locality: Option<S>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub region: Option<S>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub postal_code: Option<S>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub country: Option<S>,
}

// TODO: Check whether claims from a scope are essential or not.
impl From<&Scope> for StandardClaims<IndividualClaimRequest> {
    fn from(value: &Scope) -> Self {
        value
            .iter()
            .map(|scope_value| match scope_value {
                ScopeValue::Profile => StandardClaims {
                    name: Some(IndividualClaimRequest::default()),
                    family_name: Some(IndividualClaimRequest::default()),
                    given_name: Some(IndividualClaimRequest::default()),
                    middle_name: Some(IndividualClaimRequest::default()),
                    nickname: Some(IndividualClaimRequest::default()),
                    preferred_username: Some(IndividualClaimRequest::default()),
                    profile: Some(IndividualClaimRequest::default()),
                    picture: Some(IndividualClaimRequest::default()),
                    website: Some(IndividualClaimRequest::default()),
                    gender: Some(IndividualClaimRequest::default()),
                    birthdate: Some(IndividualClaimRequest::default()),
                    zoneinfo: Some(IndividualClaimRequest::default()),
                    locale: Some(IndividualClaimRequest::default()),
                    updated_at: Some(IndividualClaimRequest::default()),
                    ..Default::default()
                },
                ScopeValue::Email => StandardClaims {
                    email: Some(IndividualClaimRequest::default()),
                    email_verified: Some(IndividualClaimRequest::default()),
                    ..Default::default()
                },
                ScopeValue::Address => StandardClaims {
                    address: Some(IndividualClaimRequest::default()),
                    ..Default::default()
                },
                ScopeValue::Phone => StandardClaims {
                    phone_number: Some(IndividualClaimRequest::default()),
                    phone_number_verified: Some(IndividualClaimRequest::default()),
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
        let user_claims: StandardClaims<ClaimValue> = serde_json::from_value(USER_CLAIMS.clone()).unwrap();
        assert_eq!(
            user_claims,
            StandardClaims {
                name: Some(ClaimValue("Jane Doe".to_string())),
                given_name: Some(ClaimValue("Jane".to_string())),
                family_name: Some(ClaimValue("Doe".to_string())),
                middle_name: Some(ClaimValue("Middle".to_string())),
                nickname: Some(ClaimValue("JD".to_string())),
                preferred_username: Some(ClaimValue("j.doe".to_string())),
                profile: Some(ClaimValue("https://example.com/janedoe".to_string())),
                picture: Some(ClaimValue("https://example.com/janedoe/me.jpg".to_string())),
                website: Some(ClaimValue("https://example.com".to_string())),
                email: Some(ClaimValue("jane.doe@example.com".to_string())),
                updated_at: Some(ClaimValue(1311280970)),
                address: Some(ClaimValue(Address {
                    formatted: Some(ClaimValue("100 Universal City Plaza\nHollywood, CA 91608".to_string())),
                    street_address: Some(ClaimValue("100 Universal City Plaza".to_string())),
                    locality: Some(ClaimValue("Hollywood".to_string())),
                    region: Some(ClaimValue("CA".to_string())),
                    postal_code: Some(ClaimValue("91608".to_string())),
                    country: Some(ClaimValue("US".to_string())),
                })),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_request_claims() {
        // Store the user claims in the storage.
        let storage =
            MemoryStorage::new(serde_json::from_value::<StandardClaims<ClaimValue>>(USER_CLAIMS.clone()).unwrap());

        // Initialize a set of request claims.
        let request_claims = ClaimRequests {
            id_token: Some(StandardClaims::<IndividualClaimRequest> {
                name: Some(IndividualClaimRequest::default()),
                given_name: Some(IndividualClaimRequest::from_request_object(
                    IndividualClaimRequestObject {
                        essential: Some(false),
                        ..Default::default()
                    },
                )),
                family_name: Some(IndividualClaimRequest::from_request_object(
                    IndividualClaimRequestObject {
                        value: Some("Doe".to_string()),
                        ..Default::default()
                    },
                )),
                middle_name: Some(IndividualClaimRequest::from_request_object(
                    IndividualClaimRequestObject {
                        values: Some(vec!["Doe".to_string(), "Done".to_string()]),
                        ..Default::default()
                    },
                )),
                nickname: Some(IndividualClaimRequest::from_request_object(
                    IndividualClaimRequestObject {
                        essential: Some(false),
                        value: Some("JD".to_string()),
                        ..Default::default()
                    },
                )),
                updated_at: Some(IndividualClaimRequest::from_request_object(
                    IndividualClaimRequestObject {
                        essential: Some(false),
                        values: Some(vec![1311280970, 1311280971]),
                        ..Default::default()
                    },
                )),
                address: Some(IndividualClaimRequest::from_request_object(
                    IndividualClaimRequestObject {
                        essential: Some(false),
                        value: Some(Address {
                            formatted: Some(IndividualClaimRequest::from_request_object(
                                IndividualClaimRequestObject {
                                    essential: Some(false),
                                    ..Default::default()
                                },
                            )),
                            street_address: Some(IndividualClaimRequest::from_request_object(
                                IndividualClaimRequestObject {
                                    value: Some("100 Universal City Plaza".to_string()),
                                    ..Default::default()
                                },
                            )),
                            locality: Some(IndividualClaimRequest::from_request_object(
                                IndividualClaimRequestObject {
                                    values: Some(vec!["Hollywood".to_string(), "Amsterdam".to_string()]),
                                    ..Default::default()
                                },
                            )),
                            region: Some(IndividualClaimRequest::from_request_object(
                                IndividualClaimRequestObject {
                                    essential: Some(false),
                                    value: Some("CA".to_string()),
                                    ..Default::default()
                                },
                            )),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            }),
            user_claims: None,
        };

        // Fetch a selection of the user claims (based on the request claims) from the storage.
        let response_claims = storage.fetch_claims(&request_claims.id_token.unwrap());

        assert_eq!(
            response_claims,
            StandardClaims {
                name: Some(ClaimValue("Jane Doe".to_string())),
                given_name: Some(ClaimValue("Jane".to_string())),
                family_name: Some(ClaimValue("Doe".to_string())),
                middle_name: Some(ClaimValue("Middle".to_string())),
                nickname: Some(ClaimValue("JD".to_string())),
                updated_at: Some(ClaimValue(1311280970)),
                address: Some(ClaimValue(Address {
                    formatted: Some(ClaimValue("100 Universal City Plaza\nHollywood, CA 91608".to_string())),
                    street_address: Some(ClaimValue("100 Universal City Plaza".to_string())),
                    locality: Some(ClaimValue("Hollywood".to_string())),
                    region: Some(ClaimValue("CA".to_string())),
                    postal_code: Some(ClaimValue("91608".to_string())),
                    country: Some(ClaimValue("US".to_string())),
                })),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_from_scope() {
        // Assert that the combination of scopes is correctly mapped to the standard claims
        let scope = Scope::from(vec![
            ScopeValue::OpenId,
            ScopeValue::Email,
            ScopeValue::Address,
            ScopeValue::Phone,
        ]);
        assert_eq!(
            StandardClaims::from(&scope),
            StandardClaims {
                email: Some(IndividualClaimRequest::default()),
                email_verified: Some(IndividualClaimRequest::default()),
                address: Some(IndividualClaimRequest::default()),
                phone_number: Some(IndividualClaimRequest::default()),
                phone_number_verified: Some(IndividualClaimRequest::default()),
                ..Default::default()
            }
        );
    }
}
