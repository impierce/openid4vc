use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Proofs {
    pub jwt: Vec<String>,
    // TODO: add support for other proof types
}

// TODO: implement `ProofsBuilder`
