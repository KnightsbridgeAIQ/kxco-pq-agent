# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when algorithms move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
and publishes the lot. Cited here, proven there.

## What this package is

Identity for a non-human actor. A KYC-verified institution sponsors an ML-DSA-65
keypair for an agent and binds a capability scope to it at issuance.

The question a supervisor asks about an autonomous system is not "was it
encrypted" but "who authorised this, and what were they allowed to do". This
package is built to answer exactly that, and three properties hold:

**An agent cannot widen its own authority.** The scope is signed by the sponsor
at issuance and hashed on chain, so it cannot be edited afterwards. Widening
requires revoke and re-issue by the sponsor. Compromising the agent does not
enlarge what the agent may do, which is the property that makes an autonomous
key safe to deploy at all.

**An agent cannot mint another agent.** Only a KYC-verified sponsor issues an
identity. There is no path from one compromised agent to a population of them.

**Every agent traces to a named legal entity.** No anonymous mode, no
self-signed mode. When a regulator asks who authorised an action, the answer is
an institution that completed KYC, not a key of unknown provenance.

**Enforcement runs at both ends.** The relay checks scope behind the agent,
where a compromised agent cannot reach it, and `checkScope()` checks the same
signed scope in front:

```js
const decision = checkScope(agent.scope, {
  type: 'payment', amount: 4500, spentToday: 12000, recipient: '0xAbC…',
})
// { allowed: false, reason: 'amount 4500 would take today's total to 16500,
//    past maxPerDay 15000', checked: ['payments.enabled', …] }
```

It refuses offline, so an agent that cannot reach the relay still knows what it
may not do. It refuses without spending a round trip. And it names the limit that
stopped it, which a remote refusal cannot do as precisely. It fails closed
throughout: a capability the scope does not grant is denied, an action type it
does not recognise is denied, and a configured limit that cannot be judged from
the inputs given is denied rather than skipped. `checked` reports every limit
the decision actually evaluated, so a caller can see the control was applied
rather than assume it.

**Expiry is mandatory.** `expiresIn` is required at creation. An agent identity
cannot be issued without an end date, which is the default that stops a
short-lived task leaving a long-lived key behind.

## Scope

The relay's enforcement is the one that binds, because it sits where the agent
cannot influence it, and `checkScope()` is defence in depth in front of it.
Assess both: the local check for fast, offline, precise refusal, and the relay
for the guarantee.

The sponsor's KYC is an operational control at KXCO rather than a protocol one,
and it is the thing that makes attribution to a legal entity meaningful.

Actions land where they land: on Armature L1 through
[`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain), or in whatever
record the sponsor keeps, for which
[`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) is the
append-only option.

## Agility

**Inherited.** Signing primitives belong to `kxco-post-quantum`.

**Coordinated by design.** An agent identity is registered on chain and its
scope is checked by the relay, so a parameter-set change moves through the chain
and the relay before it reaches the client. That ordering is correct: an
identity nobody can verify is worse than one that waits, and it is why the
migration story for this package is the chain's rather than its own.

**The scope manifest is a signed data structure** with named capability
sections, so adding a capability class is a change the sponsor signs and the
enforcer recognises, agreed between the two rather than assumed by either.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation and
a CycloneDX SBOM at a permanent unauthenticated URL, plus an evidence bundle
from `npm run evidence` recording identity, the test run, the SBOM and the
`kxco-post-quantum` version actually installed rather than the range declared.

**Supported versions.** One line moving forward. Fixes land in the next release.

**Cost.** No hardware or runtime ceiling. Signing is one ML-DSA-65 operation per
action; the practical limits are the scope caps themselves, which are policy
rather than performance.

**Connection.** `relay.kxco.ai`, which negotiates the hybrid key exchange group
`X25519MLKEM768` under TLS 1.3. Measured 7 September 2026 with OpenSSL 3.5.6,
and reproducible:

```
echo | openssl s_client -connect relay.kxco.ai:443 -servername relay.kxco.ai \
  -groups X25519MLKEM768 -tls1_3 2>&1 | grep "Negotiated TLS1.3 group"
```

The intent is signed with ML-DSA-65 before it is sent and verified on chain
after it arrives, so the transport carries the intent rather than securing it.

## Correcting this document

Every claim here is checkable against `src/` and the README. The TLS measurement
is reproducible with the command given. If one does not match, that is a defect
worth reporting through the repository's issues.
