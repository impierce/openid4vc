use crate::serialize_unit_struct;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct Jwt;

#[derive(Debug)]
pub struct Cwt;

serialize_unit_struct!("jwt", Jwt);
serialize_unit_struct!("cwt", Cwt);

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Proof {
    Jwt { proof_type: Jwt, jwt: String },
    Cwt { proof_type: Cwt, cwt: String },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ProofType {
    Jwt,
    Cwt,
}
