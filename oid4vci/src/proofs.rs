use serde::{Deserialize, Serialize};

/// One or more proofs of possession grouped by proof type.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Proofs {
    pub jwt: Vec<String>,
    // TODO: add support for other proof types
}

// TODO: implement `ProofsBuilder`
