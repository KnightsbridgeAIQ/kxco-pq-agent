# Assessment notes

Where this package's boundary falls, what agility it has, and what constrains
its lifecycle.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) and is
published in that package's evidence bundle. It is referenced here, never
restated.

## Boundary

**What the assessed thing is.** An identity for a non-human actor: a
KYC-verified institution sponsors an ML-DSA-65 keypair for an agent and binds a
capability scope to it at issuance.

**Where the containment properties are actually enforced. This is the boundary
statement that matters most in this package.** The README states three
properties: an agent cannot widen its own authority, cannot mint another agent,
and always traces to a named institution. They hold, and a buyer needs to know
*what* holds them, because it is not this library.

- *Scope is enforced relay-side, and only relay-side.* An out-of-scope
  operation is refused before it reaches the chain. There is no client-side
  equivalent: `src/scope.js` exports `validateScope`, which checks the shape of
  a manifest at issuance, and `hashScope`, which binds it to the credential.
  Neither evaluates a proposed action against the scope. So the boundary that
  contains a compromised agent is a KXCO service, not a property of this
  library and not something the agent's own process could apply even if it
  wanted to.
- *The scope is signed by the sponsor at issuance and cannot be changed.*
  Widening requires revoke and re-issue. That part is cryptographic.
- *Sponsorship requires KYC.* That is an operational control at KXCO, not a
  protocol one.

The honest summary: the cryptography proves which agent acted and under whose
sponsorship; the limits on what that agent may do are enforced by our relay. An
assessment that credits this package with the enforcement has misplaced it.

**Required service connection.** `relay.kxco.ai`, which negotiates the hybrid
key exchange group `X25519MLKEM768` under TLS 1.3, measured 7 September 2026
with OpenSSL 3.5.6:

```
echo | openssl s_client -connect relay.kxco.ai:443 -servername relay.kxco.ai \
  -groups X25519MLKEM768 -tls1_3 2>&1 | grep "Negotiated TLS1.3 group"
```

The certificate is ECDSA P-384 from Let's Encrypt, so endpoint authentication
is classical, as it is across the public WebPKI. Since scope enforcement
happens at the far end of that connection, availability of the relay is a
functional dependency and not merely a convenience: no relay, no enforced
action.

**Retain history.** Nothing stored here. An agent's actions are recorded where
they land, on Armature L1 or in whatever audit log the sponsor keeps.

**Start and update.** No release signing of its own. Published through CI with
npm provenance.

## Agility

**Inherited, and coordinated.** Signing primitives belong to
`kxco-post-quantum`. Because an agent's identity is registered on Armature L1
and its scope is checked by the relay, a parameter-set change here is a
chain-and-relay change before it is a client change. See the same constraint in
`kxco-pq-chain`.

**The scope manifest is a data format and it has no version field.** The scope
object carries `payments`, `attestations`, `auditLog` and `credentials` keys.
It is signed at issuance, so it cannot be altered, and there is no version
marker inside it to distinguish a future shape from the current one. Adding a
capability class later is therefore a change that both signer and enforcer must
agree on out of band. Worth noting beside the version prefixes that
`kxco-pq-attest` and `kxco-pq-tls` do carry.

## Lifecycle

**This package has an unpublished release.** The tree is at **1.0.8** and npm
carries **1.0.7**. So the source here is ahead of what anyone can install, and
an assessment reading this repository is not reading the shipped artefact
unless that is reconciled. It is the only package in the family in this state.

**Supported versions.** One line moving forward, matching the family.

**Pins.** `kxco-post-quantum` is declared `^1.3.0` and the tree the evidence
bundle was last built from resolved it to **1.3.0**, against a current
primitives release of 1.7.2. `02-primitives.json` records the resolved version.

**Ceiling.** No hardware or runtime ceiling. Signing is one ML-DSA-65 operation
per action. The practical limits are the relay's rate limits and the scope
caps themselves, which are policy rather than performance.

**Blocking dependencies.** The upstream library, and the relay service, which
is ours and which is where enforcement lives. For this package the relay
dependency is stronger than elsewhere: `kxco-pq-network` can fall back to
`anchored` and lose only revocation checking, whereas an agent with no relay
has no enforced scope.

**Roadmap.** No external audit, no bug bounty. No published availability target
for the relay.

## Correcting this document

The TLS measurement is reproducible with the command given. Everything else is
checkable against `src/` and the README. If a claim does not match, that is a
defect worth reporting through the repository's issues.
