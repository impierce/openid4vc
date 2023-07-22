pub mod managers;
pub mod methods;
pub mod servers;

pub use managers::{provider::ProviderManager, relying_party::RelyingPartyManager};

use rand::{distributions::Alphanumeric, Rng};

// TODO: @damader wdyt?
pub fn generate_authorization_code(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub fn generate_nonce(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}
