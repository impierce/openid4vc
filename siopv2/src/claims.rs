use crate::{
    parse_other,
    scope::{Scope, ScopeValue},
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::skip_serializing_none;

/// Functions as the `claims` parameter inside a [`crate::AuthorizationRequest`].
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimRequests {
    pub user_claims: Option<StandardClaimsRequests>,
    pub id_token: Option<StandardClaimsRequests>,
}

impl TryFrom<serde_json::Value> for ClaimRequests {
    type Error = anyhow::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(Into::into)
    }
}

impl TryFrom<&str> for ClaimRequests {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        serde_json::from_str(value).map_err(Into::into)
    }
}

mod sealed {
    /// [`Claim`] trait that is implemented by both [`ClaimValue`] and [`ClaimRequest`].
    pub trait Claim {
        type Container<T>;
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimValue<T>(pub T);

impl<T> sealed::Claim for ClaimValue<T> {
    type Container<U> = U;
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimRequest<T>(IndividualClaimRequest<T>);

impl<T> sealed::Claim for ClaimRequest<T> {
    type Container<U> = IndividualClaimRequest<U>;
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IndividualClaimRequest<T> {
    #[default]
    Null,
    Object {
        #[serde(skip_serializing_if = "Option::is_none")]
        essential: Option<bool>,
        // Requests that the Claim be returned with a particular value.
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<T>,
        // Requests that the Claim be returned with one of a set of values, with the values appearing in order of
        // preference.
        #[serde(skip_serializing_if = "Option::is_none")]
        values: Option<Vec<T>>,
        // Other members MAY be defined to provide additional information about the requested Claims. Any members used that
        // are not understood MUST be ignored.
        #[serde(flatten, deserialize_with = "parse_other")]
        other: Option<serde_json::Map<String, serde_json::Value>>,
    },
}

macro_rules! object_member {
    ($name:ident, $type:ty) => {
        pub fn $name(mut self, v: $type) -> Self {
            match &mut self {
                Self::Object { $name, .. } => {
                    $name.replace(v);
                    self
                }
                Self::Null => Self::object().$name(v),
            }
        }
    };
}

impl<T> IndividualClaimRequest<T> {
    pub fn object() -> Self {
        Self::Object {
            essential: None,
            value: None,
            values: None,
            other: None,
        }
    }

    object_member!(essential, bool);
    object_member!(value, T);
    object_member!(values, Vec<T>);
    object_member!(other, serde_json::Map<String, serde_json::Value>);
}

/// An individual claim request as defined in [OpenID Connect Core 1.0, section 5.5.1](https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests).
/// Individual claims can be requested by simply some key with a `null` value, or by using the `essential`, `value`,
/// and `values` fields. Additional information about the requested claim MAY be added to the claim request. This
/// addition allows for more flexibility in requesting for claims that is outside the scope of the OpenID core
/// specification.
/// # Example
/// ```
/// # use siopv2::StandardClaimsRequests;
/// let claims = serde_json::from_value::<StandardClaimsRequests>(serde_json::json!({
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
/// ```
pub type StandardClaimsRequests = StandardClaims<ClaimRequest<()>>;

pub type StandardClaimsValues = StandardClaims<ClaimValue<()>>;

/// This struct represents the standard claims as defined in the
/// [OpenID Connect Core 1.0 Specification](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
/// specification. It can be used either for requesting claims using [`IndividualClaimRequest`]'s in the `claims`
/// parameter of a [`crate::AuthorizationRequest`], or for returning actual [`ClaimValue`]'s in an [`crate::IdToken`].
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StandardClaims<C: sealed::Claim> {
    #[serde(bound(
        serialize = r#"
            C::Container<String>: Serialize,
            C::Container<i64>: Serialize,
            C::Container<bool>: Serialize,
            C::Container<Address<C>>: Serialize"#,
        deserialize = r#"
            C::Container<String>: Deserialize<'de> + Default,
            C::Container<i64>: Deserialize<'de> + Default,
            C::Container<bool>: Deserialize<'de> + Default,
            C::Container<Address<C>>: Deserialize<'de> + Default"#
    ))]
    // Profile scope
    #[serde(deserialize_with = "parse_optional_claim")]
    pub name: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub family_name: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub given_name: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub middle_name: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub nickname: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub preferred_username: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub profile: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub picture: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub website: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub gender: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub birthdate: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub zoneinfo: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub locale: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub updated_at: Option<C::Container<i64>>,
    // Email scope
    #[serde(deserialize_with = "parse_optional_claim")]
    pub email: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub email_verified: Option<C::Container<bool>>,
    // Address scope
    #[serde(deserialize_with = "parse_optional_claim")]
    pub address: Option<C::Container<Address<C>>>,
    // Phone scope
    #[serde(deserialize_with = "parse_optional_claim")]
    pub phone_number: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub phone_number_verified: Option<C::Container<bool>>,
}

/// A helper function to deserialize a claim. If the claim is not present, it will be deserialized as a `None` value.
/// If the claim is present, but the value is `null`, it will be deserialized as `Some(Default::default())`.
fn parse_optional_claim<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Some(Option::<T>::deserialize(deserializer)?.unwrap_or_default()))
}

impl<C> StandardClaims<C>
where
    C: sealed::Claim,
{
    /// Takes another `StandardClaims<C>` and takes it's values for every missing `None` valued field.
    pub fn merge(&mut self, mut other: Self) {
        macro_rules! merge_if_none {
            ($($field: ident),+ $(,)?) => {
                $(
                    if self.$field.is_none() {
                        self.$field = other.$field.take();
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

// TODO: Check whether claims from a scope are essential or not.
impl From<&Scope> for StandardClaimsRequests {
    fn from(value: &Scope) -> Self {
        value
            .iter()
            .map(|scope_value| match scope_value {
                ScopeValue::Profile => StandardClaims {
                    name: Some(IndividualClaimRequest::Null),
                    family_name: Some(IndividualClaimRequest::Null),
                    given_name: Some(IndividualClaimRequest::Null),
                    middle_name: Some(IndividualClaimRequest::Null),
                    nickname: Some(IndividualClaimRequest::Null),
                    preferred_username: Some(IndividualClaimRequest::Null),
                    profile: Some(IndividualClaimRequest::Null),
                    picture: Some(IndividualClaimRequest::Null),
                    website: Some(IndividualClaimRequest::Null),
                    gender: Some(IndividualClaimRequest::Null),
                    birthdate: Some(IndividualClaimRequest::Null),
                    zoneinfo: Some(IndividualClaimRequest::Null),
                    locale: Some(IndividualClaimRequest::Null),
                    updated_at: Some(IndividualClaimRequest::Null),
                    ..Default::default()
                },
                ScopeValue::Email => StandardClaims {
                    email: Some(IndividualClaimRequest::Null),
                    email_verified: Some(IndividualClaimRequest::Null),
                    ..Default::default()
                },
                ScopeValue::Address => StandardClaims {
                    address: Some(IndividualClaimRequest::Null),
                    ..Default::default()
                },
                ScopeValue::Phone => StandardClaims {
                    phone_number: Some(IndividualClaimRequest::Null),
                    phone_number_verified: Some(IndividualClaimRequest::Null),
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

/// The Address Claim as defined in [OpenID Standard Claims](https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim).
#[skip_serializing_none]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Address<C: sealed::Claim> {
    #[serde(bound(serialize = "C::Container<String>: Serialize"))]
    #[serde(bound(deserialize = "C::Container<String>: Deserialize<'de> + Default"))]
    #[serde(deserialize_with = "parse_optional_claim")]
    pub formatted: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub street_address: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub locality: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub region: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub postal_code: Option<C::Container<String>>,
    #[serde(deserialize_with = "parse_optional_claim")]
    pub country: Option<C::Container<String>>,
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
        let user_claims: StandardClaimsValues = serde_json::from_value(USER_CLAIMS.clone()).unwrap();
        assert_eq!(
            user_claims,
            StandardClaims {
                name: Some("Jane Doe".to_string()),
                given_name: Some("Jane".to_string()),
                family_name: Some("Doe".to_string()),
                middle_name: Some("Middle".to_string()),
                nickname: Some("JD".to_string()),
                preferred_username: Some("j.doe".to_string()),
                profile: Some("https://example.com/janedoe".to_string()),
                picture: Some("https://example.com/janedoe/me.jpg".to_string()),
                website: Some("https://example.com".to_string()),
                email: Some("jane.doe@example.com".to_string()),
                updated_at: Some(1311280970),
                address: Some(Address {
                    formatted: Some("100 Universal City Plaza\nHollywood, CA 91608".to_string()),
                    street_address: Some("100 Universal City Plaza".to_string()),
                    locality: Some("Hollywood".to_string()),
                    region: Some("CA".to_string()),
                    postal_code: Some("91608".to_string()),
                    country: Some("US".to_string()),
                }),
                ..Default::default()
            }
        );
    }

    #[test]
    fn test_request_claims() {
        // Store the user claims in the storage.
        let storage = MemoryStorage::new(serde_json::from_value::<StandardClaimsValues>(USER_CLAIMS.clone()).unwrap());

        // Initialize a set of request claims.
        let request_claims = ClaimRequests {
            id_token: Some(StandardClaimsRequests {
                name: Some(IndividualClaimRequest::Null),
                given_name: Some(IndividualClaimRequest::object().essential(true)),
                family_name: Some(IndividualClaimRequest::object().value("Doe".to_string())),
                middle_name: Some(IndividualClaimRequest::object().values(vec!["Doe".to_string(), "Done".to_string()])),
                nickname: Some(IndividualClaimRequest::object().essential(true).value("JD".to_string())),
                updated_at: Some(
                    IndividualClaimRequest::object()
                        .essential(true)
                        .values(vec![1311280970, 1311280971]),
                ),
                address: Some(
                    IndividualClaimRequest::object().essential(false).value(Address {
                        formatted: Some(IndividualClaimRequest::object().essential(false)),
                        street_address: Some(
                            IndividualClaimRequest::object().value("100 Universal City Plaza".to_string()),
                        ),
                        locality: Some(
                            IndividualClaimRequest::object()
                                .values(vec!["Hollywood".to_string(), "Amsterdam".to_string()]),
                        ),
                        region: Some(
                            IndividualClaimRequest::object()
                                .essential(false)
                                .value("CA".to_string()),
                        ),
                        postal_code: Some(
                            IndividualClaimRequest::object().other(
                                serde_json::json!({
                                    "other": "member"
                                })
                                .as_object()
                                .unwrap()
                                .to_owned(),
                            ),
                        ),
                        ..Default::default()
                    }),
                ),
                ..Default::default()
            }),
            user_claims: None,
        };

        // Fetch a selection of the user claims (based on the request claims) from the storage.
        let response_claims = storage.fetch_claims(&request_claims.id_token.unwrap());

        assert_eq!(
            response_claims,
            StandardClaims {
                name: Some("Jane Doe".to_string()),
                given_name: Some("Jane".to_string()),
                family_name: Some("Doe".to_string()),
                middle_name: Some("Middle".to_string()),
                nickname: Some("JD".to_string()),
                updated_at: Some(1311280970),
                address: Some(Address {
                    formatted: Some("100 Universal City Plaza\nHollywood, CA 91608".to_string()),
                    street_address: Some("100 Universal City Plaza".to_string()),
                    locality: Some("Hollywood".to_string()),
                    region: Some("CA".to_string()),
                    postal_code: Some("91608".to_string()),
                    country: Some("US".to_string()),
                }),
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
                email: Some(IndividualClaimRequest::Null),
                email_verified: Some(IndividualClaimRequest::Null),
                address: Some(IndividualClaimRequest::Null),
                phone_number: Some(IndividualClaimRequest::Null),
                phone_number_verified: Some(IndividualClaimRequest::Null),
                ..Default::default()
            }
        );
    }
}
