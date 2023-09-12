# Self-Issued OpenID Provider v2
This is a Rust library for the [Self-Issued OpenID Provider v2](https://openid.bitbucket.io/connect/openid-connect-self-issued-v2-1_0.html) (SIOPv2) specification developed by the [OpenID
Digital Credentials Protocols
Working Group](https://openid.net/wg/digital-credentials-protocols/).

An overview of all the OpenID Digital Credentials Protocols implementation in Rust can be found [here](../README.md).

## Description
The Self-Issued OpenID Provider v2 (SIOPv2) specification enhances the capabilities of the OpenID Connect framework. OpenID Connect primarily facilitates the sharing of identity information from an OpenID Provider (OP) to a Relying Party (RP) on behalf of an End-User. In this traditional model, RPs trust identity assertions made by the OP, which acts as the issuer of these assertions.

The Self-Issued OP extends this framework by introducing the concept of an OP that is under the control of the End-User. In this scenario, the Self-Issued OP does not assert identity information about the End-User. Instead, it empowers the End-User to become the issuer of their own identity information. This allows end-users to authenticate themselves using Self-Issued ID Tokens signed with keys they control and present self-attested claims directly to RPs.

Notably, Self-Issued OPs can also present cryptographically verifiable claims issued by third parties trusted by RPs.
This is made possible by using separate specifications, such as [OpenID for Verifiable Presentations](../oid4vp), or by utilizing Aggregated and Distributed
Claims. This capability streamlines the interaction between end-users and
RPs without requiring RPs to directly communicate with the issuers of said claims.
