//! Compact JWTs and SD-JWTs as they reach the validators before any signature check (RFC 7515
//! "JWS Compact Serialization", SD-JWT "`<Issuer-signed JWT>~<Disclosure>~...`"), and the Subject
//! Syntax Types of SIOPv2 ("Subject Syntax Types", `did:<method>` and the JWK Thumbprint URN).
//! Nothing panics; the `kid` returned is the header's, completed with `iss` only when relative; a
//! parsed Subject Syntax Type prints to a string, and serializes to JSON, that parse to the same value.
#![no_main]

use std::str::FromStr as _;

use libfuzzer_sys::fuzz_target;
use oid4vc_core::jwt::extract_header;
use oid4vc_core::utils::did::extract_normalized_did_kid_from_jwt;
use oid4vc_core::utils::jwt::{get_unverified_jwt_claims, sd_jwt_to_jwt};
use oid4vc_core::{DidMethod, SubjectSyntaxType};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let jwt = sd_jwt_to_jwt(input);
    assert!(input.starts_with(jwt), "the JWT of an SD-JWT is its prefix");
    let _ = get_unverified_jwt_claims(&serde_json::Value::String(input.to_owned()));
    let _ = extract_header(input);
    if let Ok(kid) = extract_normalized_did_kid_from_jwt(input) {
        let (header_kid, _) = extract_header(jwt).expect("a normalized kid comes from a decodable header");
        assert!(
            kid.ends_with(&header_kid),
            "the normalized kid ends with the header's: {kid}"
        );
        if !header_kid.starts_with('#') {
            assert_eq!(kid, header_kid, "an absolute kid is returned as is");
        }
    }

    if let Ok(subject_syntax_type) = SubjectSyntaxType::from_str(input) {
        let printed = subject_syntax_type.to_string();
        assert_eq!(
            SubjectSyntaxType::from_str(&printed).ok().as_ref(),
            Some(&subject_syntax_type)
        );
        let json = serde_json::to_value(&subject_syntax_type).expect("a subject syntax type serializes");
        let again: SubjectSyntaxType = serde_json::from_value(json).expect("a serialized subject syntax type parses");
        assert_eq!(again, subject_syntax_type);
    }
    for did_method in [
        DidMethod::from_str(input).ok(),
        DidMethod::from_str_with_namespace(input).ok(),
    ]
    .into_iter()
    .flatten()
    {
        assert_eq!(did_method.to_string(), input, "a DID method prints as it was parsed");
        // DID Core: `method-name = 1*method-char`, `method-char = %x61-7A / DIGIT`.
        let method_name = input.split(':').nth(1).unwrap_or_default();
        assert!(
            method_name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "a DID method name is lowercase ASCII letters and digits: {input}"
        );
    }
});
