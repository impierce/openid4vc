# DIF Presentation Exchange 2.0.0
This is Rust a library for the [DIF Presentation Exchange
2.0.0](https://identity.foundation/presentation-exchange/spec/v2.0.0/) specification developed by the [Decentralized
Identity Foundation](https://identity.foundation/).

## Description
This specification addresses the need for a standardized way to demand and submit proofs in identity systems. It introduces a Presentation Definition format for Verifiers to express proof requirements and a Presentation Submission format for Holders to describe proof submissions.

Key Points:
* The specification is format-agnostic, supporting various Claim formats as long as they can be serialized as JSON.
* It is also transport-envelope agnostic, allowing the conveyance of data via different methods like [OpenID4VP](../oid4vp), OpenID Connect, DIDComm, or Credential Handler API.
* The goal is to promote unified procedures and reduce redundant code.
* The specification does not define transport protocols or specific endpoints but encourages their use in other projects that define such mechanisms.
