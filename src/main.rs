use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

mod old {
    use super::*;

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
    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    #[serde(default, deny_unknown_fields)]
    pub struct StandardClaims {
        // Profile scope
        pub name: Option<Claim<String>>,
        pub family_name: Option<Claim<String>>,
        pub given_name: Option<Claim<String>>,
        pub birthdate: Option<Claim<String>>,
        // Email scope
        pub email: Option<Claim<String>>,
        pub email_verified: Option<Claim<bool>>,
        // Phone scope
        pub phone_number: Option<Claim<String>>,
        pub phone_number_verified: Option<Claim<bool>>,
    }
}

mod new {
    use serde::{de::DeserializeOwned, Deserializer};

    use super::*;

    /// [`Claim`] trait that is implemented by both [`ClaimValue`] and [`IndividualClaimRequest`].
    pub trait Claim: Default + Clone + DeserializeOwned {
        type ValueType;
        type ClaimType<S>: Claim<ValueType = S> + Serialize
        where
            S: Serialize + Default + Clone + DeserializeOwned;
    }

    #[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
    pub struct ClaimValue<T = ()>(pub T);

    impl<T: Serialize + Default + Clone + DeserializeOwned> Claim for ClaimValue<T> {
        type ValueType = T;
        type ClaimType<S> = ClaimValue<S> where S: Serialize + Default + Clone + DeserializeOwned;
    }

    #[derive(Default, Debug, Clone, PartialEq, Deserialize, Serialize)]
    pub struct IndividualClaimRequest<T = ()>(Option<IndividualClaimRequestObject<T>>);

    impl<T: Serialize + Default + Clone + DeserializeOwned> Claim for IndividualClaimRequest<T> {
        type ValueType = T;
        type ClaimType<S> = IndividualClaimRequest<S> where S: Serialize + Default + Clone + DeserializeOwned;
    }

    // impl<T> IndividualClaimRequest<T> {
    //     pub fn from_request_object(request: IndividualClaimRequestObject<T>) -> Self {
    //         IndividualClaimRequest(Some(request))
    //     }
    // }

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
    pub struct StandardClaims<C: Claim> {
        // Profile scope
        #[serde(deserialize_with = "parse_optional_claim")]
        pub name: Option<C::ClaimType<String>>,
        #[serde(deserialize_with = "parse_optional_claim")]
        pub family_name: Option<C::ClaimType<String>>,
        #[serde(deserialize_with = "parse_optional_claim")]
        pub given_name: Option<C::ClaimType<String>>,
        #[serde(deserialize_with = "parse_optional_claim")]
        pub birthdate: Option<C::ClaimType<String>>,
        // Email scope
        #[serde(deserialize_with = "parse_optional_claim")]
        pub email: Option<C::ClaimType<String>>,
        #[serde(deserialize_with = "parse_optional_claim")]
        pub email_verified: Option<C::ClaimType<bool>>,
        // Phone scope
        #[serde(deserialize_with = "parse_optional_claim")]
        pub phone_number: Option<C::ClaimType<String>>,
        #[serde(deserialize_with = "parse_optional_claim")]
        pub phone_number_verified: Option<C::ClaimType<bool>>,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_old() {
        let claims = serde_json::from_value::<old::StandardClaims>(json!({
            "name": null,
            "family_name": {
              "essential": true
            },
            "given_name": null,
            "birthdate": {
                "essential": true,
                "between": [
                   "1970-01-01",
                    "2000-01-01"
               ]
        }}))
        .unwrap();
        dbg!(claims);
    }

    #[test]
    fn test_new() {
        let claims = serde_json::from_value::<new::StandardClaims<new::IndividualClaimRequest>>(json!({
            "name": null,
            "family_name": {
              "essential": true
            },
            "given_name": null,
            "birthdate": {
                "essential": true,
                "between": [
                   "1970-01-01",
                    "2000-01-01"
               ]
        }}))
        .unwrap();
        dbg!(claims);
    }

    #[test]
    fn test_new2() {
        let claims = serde_json::from_value::<new::StandardClaims<new::ClaimValue>>(json!({
            "name": null,
            "family_name": {
              "essential": true
            },
            "given_name": null,
            "birthdate": {
                "essential": true,
                "between": [
                   "1970-01-01",
                    "2000-01-01"
               ]
        }}))
        .unwrap();
        dbg!(claims);
    }
}

fn main() {}
