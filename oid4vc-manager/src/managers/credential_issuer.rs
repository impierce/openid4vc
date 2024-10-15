use crate::storage::Storage;
use anyhow::Result;
use oid4vc_core::Subject;
use oid4vci::{
    credential_format_profiles::CredentialFormatCollection,
    credential_issuer::{
        authorization_server_metadata::AuthorizationServerMetadata,
        credential_issuer_metadata::CredentialIssuerMetadata, CredentialIssuer,
    },
    credential_offer::{CredentialOffer, CredentialOfferParameters, Grants},
};
use reqwest::Url;
use std::{net::TcpListener, sync::Arc};

#[derive(Clone)]
pub struct CredentialIssuerManager<S: Storage<CFC>, CFC: CredentialFormatCollection> {
    pub credential_issuer: CredentialIssuer<CFC>,
    pub subject: Arc<dyn Subject>,
    pub storage: S,
    pub listener: Arc<TcpListener>,
}

impl<S: Storage<CFC>, CFC: CredentialFormatCollection> CredentialIssuerManager<S, CFC> {
    pub fn new(listener: Option<TcpListener>, storage: S, subject: Arc<dyn Subject>) -> Result<Self> {
        // `TcpListener::bind("127.0.0.1:0")` will bind to a random port.
        let listener = listener.unwrap_or_else(|| TcpListener::bind("127.0.0.1:0").unwrap());
        let issuer_url: Url = format!("http://{:?}", listener.local_addr()?).parse()?;
        Ok(Self {
            credential_issuer: CredentialIssuer {
                subject: subject.clone(),
                metadata: CredentialIssuerMetadata {
                    credential_issuer: issuer_url.clone(),
                    authorization_servers: vec![],
                    credential_endpoint: issuer_url.join("/credential")?,
                    batch_credential_endpoint: Some(issuer_url.join("/batch_credential")?),
                    deferred_credential_endpoint: None,
                    notification_endpoint: None,
                    credential_response_encryption: None,
                    credential_identifiers_supported: None,
                    signed_metadata: None,
                    display: None,
                    credential_configurations_supported: storage.get_credential_configurations_supported(),
                },
                authorization_server_metadata: AuthorizationServerMetadata {
                    issuer: issuer_url.clone(),
                    authorization_endpoint: Some(issuer_url.join("/authorize")?),
                    token_endpoint: Some(issuer_url.join("/token")?),
                    pre_authorized_grant_anonymous_access_supported: Some(true),
                    ..Default::default()
                },
            },
            subject,
            storage,
            listener: Arc::new(listener),
        })
    }

    pub fn credential_issuer_url(&self) -> Result<Url> {
        Ok(self.credential_issuer.metadata.credential_issuer.clone())
    }

    pub fn credential_offer(&self) -> Result<CredentialOfferParameters> {
        let credential_configuration_ids: Vec<String> = self
            .credential_issuer
            .metadata
            .credential_configurations_supported
            .iter()
            .map(|credential| credential.0.clone())
            .collect();
        Ok(CredentialOfferParameters {
            credential_issuer: self.credential_issuer.metadata.credential_issuer.clone(),
            credential_configuration_ids,
            grants: Some(Grants {
                authorization_code: self.storage.get_authorization_code(),
                pre_authorized_code: self.storage.get_pre_authorized_code(),
            }),
        })
    }

    pub fn credential_offer_uri(&self) -> Result<Url> {
        let issuer_url = self.credential_issuer.metadata.credential_issuer.clone();
        Ok(issuer_url.join("/credential_offer")?)
    }

    pub fn credential_offer_query(&self, by_reference: bool) -> Result<String> {
        if by_reference {
            Ok(CredentialOffer::CredentialOfferUri(self.credential_offer_uri()?).to_string())
        } else {
            Ok(CredentialOffer::CredentialOffer(Box::new(self.credential_offer()?)).to_string())
        }
    }
}

#[test]
fn test() {
    let json = serde_json::json!(
        {
            "issuer": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid",
            "authorization_endpoint": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid/authorize",
            "pushed_authorization_request_endpoint": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid/par",
            "token_endpoint": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid/token",
            "jwks_uri": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid/jwks",
            "scopes_supported": [
              "openid"
            ],
            "response_types_supported": [
              "code",
              "id_token",
              "vp_token"
            ],
            "response_modes_supported": [
              "query",
              "fragment"
            ],
            "grant_types_supported": [
              "authorization_code",
              "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            "subject_types_supported": [
              "public"
            ],
            "id_token_signing_alg_values_supported": [
              "ES256"
            ],
            "credential_issuer": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid",
            "credential_endpoint": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid/credential",
            "credential_configurations_supported": {
              "pid_vc+sd-jwt": {
                "format": "vc+sd-jwt",
                "vct": "vc+sd-jwt ID",
                "cryptographic_binding_methods_supported": [
                  "did:web",
                  "did:ebsi",
                  "did:jwk"
                ],
                "credential_signing_alg_values_supported": [
                  "ES256",
                  "EdDSA",
                  "RSA",
                  "ES256K"
                ],
                "display": [
                  {
                    "name": "Persoonlijk ID",
                    "background_color": "#0c2a8d",
                    "text_color": "#ffffff",
                    "background_image": {
                      "url": "https://demopidprovider.acc.credenco.com/card_background.png",
                      "alt_text": "Persoonlijk ID gestylede achtergrond"
                    }
                  },
                  {
                    "name": "Persoonlijk ID",
                    "locale": "nl-NL",
                    "background_color": "#0c2a8d",
                    "text_color": "#ffffff",
                    "background_image": {
                      "url": "https://demopidprovider.acc.credenco.com/card_background.png",
                      "alt_text": "Persoonlijk ID gestylede achtergrond"
                    }
                  },
                  {
                    "name": "Personal ID",
                    "locale": "en-GB",
                    "background_color": "#0c2a8d",
                    "text_color": "#ffffff",
                    "background_image": {
                      "url": "https://demopidprovider.acc.credenco.com/card_background.png",
                      "alt_text": "Personal ID styled background"
                    }
                  }
                ],
                "credential_definition": {
                  "type": [
                    "VerifiableCredential",
                    "Pid"
                  ],
                  "credentialSubject": {
                    "resident_house_number": {
                      "display": [
                        {
                          "name": "Woonhuisnummer"
                        },
                        {
                          "name": "Woonhuisnummer",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential house number",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "given_name_birth": {
                      "display": [
                        {
                          "name": "Voornamen bij geboorte"
                        },
                        {
                          "name": "Voornamen bij geboorte",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Given name at time of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "family_name_birth": {
                      "display": [
                        {
                          "name": "Familienaam bij geboorte"
                        },
                        {
                          "name": "Familienaam bij geboorte",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Family name at time of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "age_birth_year": {
                      "display": [
                        {
                          "name": "Geboortejaar"
                        },
                        {
                          "name": "Geboortejaar",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Year of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "age_in_years": {
                      "display": [
                        {
                          "name": "Leeftijd in jaren"
                        },
                        {
                          "name": "Leeftijd in jaren",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Age in years",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "age_over_21": {
                      "display": [
                        {
                          "name": "Jonger dan 18"
                        },
                        {
                          "name": "Jonger dan 18",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Under the age of 18",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "age_over_18": {
                      "display": [
                        {
                          "name": "Ouder dan 18"
                        },
                        {
                          "name": "Ouder dan 18",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Age over 18",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "issuing_jurisdiction": {
                      "display": [
                        {
                          "name": "Jurisdictie"
                        },
                        {
                          "name": "Jurisdictie",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "issuing Jurisdiction",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "issuing_country": {
                      "display": [
                        {
                          "name": "Land van uitgifte"
                        },
                        {
                          "name": "Land van uitgifte",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Issuing country",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "administrative_number": {
                      "display": [
                        {
                          "name": "Administratief nummer"
                        },
                        {
                          "name": "Administratief nummer",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Administrative number",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "document_number": {
                      "display": [
                        {
                          "name": "Documentnummer"
                        },
                        {
                          "name": "Documentnummer",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Document number",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "nationality": {
                      "display": [
                        {
                          "name": "Nationaliteit"
                        },
                        {
                          "name": "Nationaliteit",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Nationality",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "gender": {
                      "display": [
                        {
                          "name": "Geslacht"
                        },
                        {
                          "name": "Geslacht",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Gender",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "family_name": {
                      "display": [
                        {
                          "name": "Familienaam"
                        },
                        {
                          "name": "Familienaam",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Family name",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_street": {
                      "display": [
                        {
                          "name": "Woonstraat"
                        },
                        {
                          "name": "Woonstraat",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential street",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_postal_code": {
                      "display": [
                        {
                          "name": "Woonpostcode"
                        },
                        {
                          "name": "Woonpostcode",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential postal code",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_city": {
                      "display": [
                        {
                          "name": "Woonplaats"
                        },
                        {
                          "name": "Woonplaats",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential city",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_state": {
                      "display": [
                        {
                          "name": "Woonprovincie"
                        },
                        {
                          "name": "Woonprovincie",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential state",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_country": {
                      "display": [
                        {
                          "name": "Woonland"
                        },
                        {
                          "name": "Woonland",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential Country",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_address": {
                      "display": [
                        {
                          "name": "Woonadres"
                        },
                        {
                          "name": "Woonadres",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential address",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_city": {
                      "display": [
                        {
                          "name": "Geboorte plaats"
                        },
                        {
                          "name": "Geboorte plaats",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "City of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_state": {
                      "display": [
                        {
                          "name": "Geboorte provincie"
                        },
                        {
                          "name": "Geboorte provincie",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "State of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_country": {
                      "display": [
                        {
                          "name": "Geboorte land"
                        },
                        {
                          "name": "Geboorte land",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Country of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_place": {
                      "display": [
                        {
                          "name": "Geboorte plaats"
                        },
                        {
                          "name": "Geboorte plaats",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Place of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_date": {
                      "display": [
                        {
                          "name": "Geboortedatum"
                        },
                        {
                          "name": "Geboortedatum",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Date of borth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "given_name": {
                      "display": [
                        {
                          "name": "Voornamen"
                        },
                        {
                          "name": "Voornamen",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Given name",
                          "locale": "en-US"
                        }
                      ]
                    }
                  }
                }
              },
              "pid_jwt_vc_json": {
                "format": "jwt_vc_json",
                "cryptographic_binding_methods_supported": [
                  "did:web",
                  "did:ebsi",
                  "did:jwk"
                ],
                "credential_signing_alg_values_supported": [
                  "ES256",
                  "EdDSA",
                  "RSA",
                  "ES256K"
                ],
                "display": [
                  {
                    "name": "Persoonlijk ID",
                    "background_color": "#0c2a8d",
                    "text_color": "#ffffff",
                    "background_image": {
                      "url": "https://demopidprovider.acc.credenco.com/card_background.png",
                      "alt_text": "Persoonlijk ID gestylede achtergrond"
                    }
                  },
                  {
                    "name": "Persoonlijk ID",
                    "locale": "nl-NL",
                    "background_color": "#0c2a8d",
                    "text_color": "#ffffff",
                    "background_image": {
                      "url": "https://demopidprovider.acc.credenco.com/card_background.png",
                      "alt_text": "Persoonlijk ID gestylede achtergrond"
                    }
                  },
                  {
                    "name": "Personal ID",
                    "locale": "en-GB",
                    "background_color": "#0c2a8d",
                    "text_color": "#ffffff",
                    "background_image": {
                      "url": "https://demopidprovider.acc.credenco.com/card_background.png",
                      "alt_text": "Personal ID styled background"
                    }
                  }
                ],
                "credential_definition": {
                  "type": [
                    "VerifiableCredential",
                    "VerifiableAttestation",
                    "Pid"
                  ],
                  "credentialSubject": {
                    "resident_house_number": {
                      "display": [
                        {
                          "name": "Woonhuisnummer"
                        },
                        {
                          "name": "Woonhuisnummer",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential house number",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "given_name_birth": {
                      "display": [
                        {
                          "name": "Voornamen bij geboorte"
                        },
                        {
                          "name": "Voornamen bij geboorte",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Given name at time of birthe",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "family_name_birth": {
                      "display": [
                        {
                          "name": "Familienaam bij geboorte"
                        },
                        {
                          "name": "Familienaam bij geboorte",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Family name at time of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "age_birth_year": {
                      "display": [
                        {
                          "name": "Geboortejaar"
                        },
                        {
                          "name": "Geboortejaar",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Year of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "age_in_years": {
                      "display": [
                        {
                          "name": "Leeftijd in jaren"
                        },
                        {
                          "name": "Leeftijd in jaren",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Age in years",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "age_over_21": {
                      "display": [
                        {
                          "name": "Ouder dan 21"
                        },
                        {
                          "name": "Ouder dan 21",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Under the age of 18",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "age_over_18": {
                      "display": [
                        {
                          "name": "Ouder dan 18"
                        },
                        {
                          "name": "Ouder dan 18",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Age over 18",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "issuing_jurisdiction": {
                      "display": [
                        {
                          "name": "Jurisdictie"
                        },
                        {
                          "name": "Jurisdictie",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "issuing Jurisdiction",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "issuing_country": {
                      "display": [
                        {
                          "name": "Land van uitgifte"
                        },
                        {
                          "name": "Land van uitgifte",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Issuing country",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "administrative_number": {
                      "display": [
                        {
                          "name": "Administratief nummer"
                        },
                        {
                          "name": "Administratief nummer",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Administrative number",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "document_number": {
                      "display": [
                        {
                          "name": "Documentnummer"
                        },
                        {
                          "name": "Documentnummer",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Document number",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "nationality": {
                      "display": [
                        {
                          "name": "Nationaliteit"
                        },
                        {
                          "name": "Nationaliteit",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Nationality",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "gender": {
                      "display": [
                        {
                          "name": "Geslacht"
                        },
                        {
                          "name": "Geslacht",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Gender",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "family_name": {
                      "display": [
                        {
                          "name": "Familienaam"
                        },
                        {
                          "name": "Familienaam",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Family name",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_street": {
                      "display": [
                        {
                          "name": "Woonstraat"
                        },
                        {
                          "name": "Woonstraat",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential street",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_postal_code": {
                      "display": [
                        {
                          "name": "Woonpostcode"
                        },
                        {
                          "name": "Woonpostcode",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential postal code",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_city": {
                      "display": [
                        {
                          "name": "Woonplaats"
                        },
                        {
                          "name": "Woonplaats",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential city",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_state": {
                      "display": [
                        {
                          "name": "Woonprovincie"
                        },
                        {
                          "name": "Woonprovincie",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential state",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_country": {
                      "display": [
                        {
                          "name": "Woonland"
                        },
                        {
                          "name": "Woonland",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential Country",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "resident_address": {
                      "display": [
                        {
                          "name": "Woonadres"
                        },
                        {
                          "name": "Woonadres",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Residential address",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_city": {
                      "display": [
                        {
                          "name": "Geboorte plaats"
                        },
                        {
                          "name": "Geboorte plaats",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "City of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_state": {
                      "display": [
                        {
                          "name": "Geboorte provincie"
                        },
                        {
                          "name": "Geboorte provincie",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "State of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_country": {
                      "display": [
                        {
                          "name": "Geboorte land"
                        },
                        {
                          "name": "Geboorte land",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Country of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_place": {
                      "display": [
                        {
                          "name": "Geboorte plaats"
                        },
                        {
                          "name": "Geboorte plaats",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Place of birth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "birth_date": {
                      "display": [
                        {
                          "name": "Geboortedatum"
                        },
                        {
                          "name": "Geboortedatum",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Date of borth",
                          "locale": "en-US"
                        }
                      ]
                    },
                    "given_name": {
                      "display": [
                        {
                          "name": "Voornamen"
                        },
                        {
                          "name": "Voornamen",
                          "locale": "nl-NL"
                        },
                        {
                          "name": "Given name",
                          "locale": "en-US"
                        }
                      ]
                    }
                  }
                }
              }
            },
            "batch_credential_endpoint": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid/batch_credential",
            "deferred_credential_endpoint": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid/credential_deferred",
            "display": [
              {
                "name": "Credenco B.V.",
                "logo": {
                  "url": "https://demopidprovider.acc.credenco.com/card_logo.png",
                  "alt_text": "Credenco logo"
                }
              },
              {
                "name": "Credenco B.V.",
                "locale": "nl-NL",
                "logo": {
                  "url": "https://demopidprovider.acc.credenco.com/card_logo.png",
                  "alt_text": "Credenco logo"
                }
              },
              {
                "name": "Credenco B.V.",
                "locale": "en-US",
                "logo": {
                  "url": "https://demopidprovider.acc.credenco.com/card_logo.png",
                  "alt_text": "Credenco logo"
                }
              }
            ],
            "authorization_server": "https://wallet.acc.credenco.com/public/8c12af10-0847-43d8-9421-03c62fbbadb0/pid"
          }
    );

    let metadata: CredentialIssuerMetadata = serde_json::from_value(json).unwrap();

    println!("{:#?}", metadata);
}
