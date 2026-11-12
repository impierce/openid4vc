//! Credential Offers (OID4VCI, "Credential Offer"): the `openid-credential-offer://` URL form, by
//! value and by reference, and the Credential Offer Parameters as JSON. Arbitrary input never
//! panics, and whatever parses survives a round trip: a parsed offer prints to a URL that parses to
//! the same offer, and parsed parameters serialize to JSON that deserializes to the same value.
#![no_main]

use std::str::FromStr as _;

use libfuzzer_sys::fuzz_target;
use oid4vci::credential_offer::{CredentialOffer, CredentialOfferParameters};

fn round_trip(offer: &CredentialOffer) {
    let url = offer.to_string();
    let again = CredentialOffer::from_str(&url).expect("a printed credential offer parses");
    assert_eq!(&again, offer);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(parameters) = serde_json::from_slice::<CredentialOfferParameters>(data) {
        // Through JSON text, as on the wire (see `presentation_messages` for why not `Value`).
        let json = serde_json::to_vec(&parameters).expect("credential offer parameters serialize");
        let again: CredentialOfferParameters =
            serde_json::from_slice(&json).expect("serialized credential offer parameters parse");
        assert_eq!(again, parameters);
        round_trip(&CredentialOffer::CredentialOffer(Box::new(parameters)));
    }

    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(offer) = CredentialOffer::from_str(input) {
        round_trip(&offer);
    }
});
