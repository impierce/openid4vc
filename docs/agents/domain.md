# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root, or
- **`GLOSSARY-MAP.md`** at the repo root if it exists: it points at one `GLOSSARY.md` per context. Read each one relevant to the topic.
- **`docs/adr/`**: read ADRs that touch the area you're about to work in. In multi-context repos, also check `src/<context>/docs/adr/` for context-scoped decisions.
- **`docs/DESIGN.md`**: the architecture, including which specification each crate tracks.

If `GLOSSARY.md` doesn't exist, **proceed silently**. Don't flag its absence; don't suggest creating it upfront. The `/domain-modeling` skill (reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates it lazily when terms or decisions actually get resolved.

## File structure

Single-context repo (this one):

```
/
├── GLOSSARY.md                        ← created lazily
├── docs/
│   ├── DESIGN.md
│   ├── FEATURES.md
│   └── adr/
│       ├── 0001-default-branch-main.md
│       └── 0002-independent-crate-versions.md
├── oid4vc-core/  oid4vci/  oid4vp/  siopv2/  oid4vc-manager/
```

The five crates are one bounded context: they share the vocabulary of the OpenID4VC
specifications (Credential Issuer, Wallet, Verifier, Credential Offer, Authorization Request,
VP Token, DCQL) and the names in code follow the specifications' names. Do not split the
glossary per crate.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `GLOSSARY.md`, which in turn follows the specification's term. Don't drift to synonyms the glossary explicitly avoids (for example "verifier" for the OID4VP party is right, "relying party" is SIOPv2's word for the same role; "holder" is a role, "wallet" is the software).

If the concept you need isn't in the glossary yet, that's a signal: either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0003 (identity-kit replaces the identity_* crates), but worth reopening because…_
