use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, PartialEq, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Claim {
    // Profile Scope
    Name,
    FamilyName,
    GivenName,
    MiddleName,
    Nickname,
    PreferredUsername,
    Profile,
    Picture,
    Website,
    Gender,
    Birthdate,
    Zoneinfo,
    Locale,
    UpdatedAt,
    // Email Scope
    Email,
    EmailVerified,
    // Address Scope
    Address,
    // Phone Scope
    PhoneNumber,
    PhoneNumberVerified,
}
